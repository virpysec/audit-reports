# PasswordStore Audit Report
**Produced By virpy**

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Roles](#roles)
- [Executive Summary](#executive-summary)
  - [Issues found](#issues-found)
- [Findings](#findings)
  - [High](#high)
  - [Informational](#informational)
# Protocol Summary

A smart contract application for storing a password. Users should be able to store a password and then retrieve it later. Others should not be able to access the password. 

# Disclaimer

The virpy team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details 

**The findings described in this document correspond to the following commit hash**
```
2e8f81e263b3a9d18fab4fb5c46805ffc10a9990
```

## Scope 
```
./src/
└── PasswordStore.sol
```

## Roles

- Owner: The user who can set the password and read the password.
- Outsiders: No one else should be able to set or read the password.

# Executive Summary

Two high vulnerabilities were found that completely break the functionality of the protocol.

## Issues found

   - High: 2
   - Medium: 0
   - Low: 0
   - Info: 1
   - Total: 3

# Findings
## High
### [H-1] Password variable stored on-chain means it is visible to anyone

**Description:** All data stored on-chain is visible to anyone and can be read directly from the blockchain.
The `PasswordStore::s_password` variable is intented to be a private variable that can only be read by the owner of the contract, however in this current implementation, anyone can read it.

**Impact:** Anyone can read the private password, severely breaking the functionality of the protocol.

**Proof of Concept:** (Proof of Code)
The below test case shows how anyone can read the password directly from the blockchain:

1. Deploy the contract on a local anvil chain
```bash
make deploy
```

2. Check the storage slots in the deployed contract
```
cast storage <address here> 1 --rpc-url http://127.0.0.1:8545
```

'1' is the storage slot for the s_password variable

3. Parsing the resulting hex to string you get the string 'myPassword'
```bash
cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
```

4. This is the password that is set in `DeployPasswordStore.s.sol`

**Recommended Mitigation:** Due to this, the overall architecture of the contract should be re-thought. A possibility is to encrypt the password off-chain, and then store the encrypted password on-chain.
<br>

### [H-2] `PasswordStore::setPassword` has no access controls, non-owner can change the password

**Description:** The `PasswordStore::setPassword` function is meant to only be able to be called by the owner of the contract as it is the function that sets a new password (updates `PasswordStore::s_password`). However, anyone can call this function, including non-owners

```solidity
    //@audit-issue Non-owner can set a password here - Missing access control
    function setPassword(string memory newPassword) external {
-->     //No access controls
        s_password = newPassword;
        emit SetNetPassword();
    }
```

**Impact:** A non-owner could call this function on the owners contract and override the owners saved password by inputting their own password. This breaks the contracts intended functionality.

**Proof of Concept:** Add the following to the `PasswordStore.t.sol` test file:
<details>
<summary>Code</summary>

```solidity
    function test_anyone_can_set_password(address randomAddress) public {
        vm.assume(randomAddress != owner);
        vm.prank(randomAddress);
        string memory expectedPassword = "myNewPassword";
        passwordStore.setPassword(expectedPassword);

        vm.prank(owner);
        string memory actualPassword = passwordStore.getPassword();

        assertEq(actualPassword, expectedPassword);
    }
```
</details>
<br>

This shows that a non-owner can successfully call the setPassword function and change the password on the owners contract

**Recommended Mitigation:** Add access control to the `PasswordStore::setPassword` function, an example is below:
```solidity
if(msg.sender != s_owner){
    revert PasswordStore__NotOwner();
}
```
## Informational
### [I-1] Incorrect `PasswordStore::getPassword` natspec documentation states input parameter when there is no input parameter

**Description:** The `PasswordStore::getPassword` function does not take any variables as an input, even though the natspec states it does
```solidity
    /*
     * @notice This allows only the owner to retrieve the password.
-->  * @param newPassword The new password to set.
     */
```
**Impact:** The natspec is incorrect

**Recommended Mitigation:** Remove the incorrect natspec line
```diff
-    * @param newPassword The new password to set.
``` 










