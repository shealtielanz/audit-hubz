# Scalable Airdrop System Audit Report

Reviewed by: shealtiielanzz ([@shealtielanzz](https://twitter.com/shealtielanzz))

Prepared For: Airdrop

Review Date(s): `1/05/25 - 1/06/25`


## <br/> shealtielanzz Background

shealtielanz is an upcoming and well-profounded Security Researcher, winning and coming out top in contests hosted by top platforms by the likes of [Code4rena](https://code4rena.com/), [Sherlock](https://audits.sherlock.xyz/), He is proficient in Func, SwayLang, Solidity & Rust.

He is well known for his Sway and Rust contributions, creating [Sway CTFs](https://github.com/shealtielanz/Simply-Sway-CTFs) to onboard new Security Researchers to the Fuel Blockchain, and his novel Invention of the [Flash Loan Predicate](https://github.com/shealtielanz/Flash_Sync) used in the Fuel Blockchain.

For private audit or consulting requests, please reach out to me via:
- Twitter `@shealtielanzz`.

## <br/> Protocol Summary

Scalable Airdrop System is an implementation of a Scalable Airdrop System for the TON blockchain. It can be used to distribute Jettons on-chain to any number of wallets.

## <br/> Scope

Repo: [airdrop](https://github.com/Gusarich/airdrop.git)

Review Hash: [e1b1a8e544fb0d68eaeed9a93210ffca045917b7](https://github.com/Gusarich/airdrop/tree/e1b1a8e544fb0d68eaeed9a93210ffca045917b7)

In-Scope Contracts
- `contracts/airdrop_helper.fc`
- `contracts/airdrop.fc`
- `contracts/constants.fc`
- `contracts/scheme.tlb`
- `contracts/jetton/jetton_minter.fc`
- `contracts/jetton/jetton_wallet.fc`
- `contracts/jetton/jetton-utils.fc`
- `contracts/jetton/op-codes.fc`

Deployment Chain(s)
- The Open Network(TON).

## <br/> Summary of Findings
> Only 2 high & 1 medium severity bugs were found during the sandboxed period of this audit!


|  Identifier  | Title                        | Severity      |
| ------ | ---------------------------- | ------------- |
| `H-01` | [Incomplete validation of Merkle proof allows an attacker to steal all the jettons owned by the airdrop.fc](#h-01-incomplete-validation-of-merkle-proof-allows-an-attacker-to-steal-all-the-jettons-owned-by-the-airdrop) | `HIGH` |
| `H-02` | [Front-running is possible, allowing an attacker to burn all the owner's tokens, thereby grieving the airdrop.](#-h-02-front-running-is-possible-allowing-an-attacker-to-burn-all-the-owners-tokens-thereby-grieving-the-airdrop) | `HIGH` |
| `M-01` | [Airdrop helper doesn't handle bounced messages, leading to loss of funds if the messages for claim bounce back for any reason.](#-m-01-airdrop-helper-doesnt-handle-bounced-messages-leading-to-loss-of-funds-if-the-messages-for-claim-bounce-back-for-any-reason) | `MED` |

### [H-01] Incomplete validation of Merkle proof allows an attacker to steal all the jettons owned by the airdrop

#### Details 
The airdrop.fc contract implements a Merkle proof-based airdrop mechanism but when the `op == op::process_claim` which allows for claiming of the airdrops, the `airdrop.fc` doesn't validate the proof completely, allowing an attacker to forge a fake proof which still contains the merkle root of the `airdrop.fc`, create a helper contract with the false proof, then use it to claim any arbitrary amount of tokens from the `airdrop.fc` contract.

	1.	forge a fake proof that shares the same merkle root as the legitimate tree.
	2.	Embed arbitrary data (for instance, their own wallet and amount) in a fake dictionary.
	3.	deploy a helper contract using the fake proof.
	4.	pass all checks and claim unearned jettons.
 
The issue is that the logic validates with the user inputted proof, allowing the attacker the ability to craft a proof with same merkle root of the airdrop.fc, the crafted proof will also contain the attacker details and arbitrary amount in the `dict`, given the proof and it's hash, he can create a helper contract with those details to bypass all checks and claim unmerited airdrops.
**vulnerable code**
```c++
(slice cs, int exotic?) = proof_cell.begin_parse_exotic();
throw_unless(42, exotic?);
throw_unless(43, cs~load_uint(8) == 3);
throw_unless(44, data::merkle_root == cs~load_uint(256));
```
It only checks that the merkle root matches `data::merkle_root` but does not validate the merkle path that links the index and its corresponding dict entry to the root.


**The check:**
```c++
throw_unless(error::wrong_sender, equal_slices(context::sender, helper_address(helper_stateinit(proof_cell.cell_hash(), index))));
```
It only checks the caller’s address matches a known derivation of the (false proof hash + index) butt since the attacker contruls both, they can compute the expected address and predeploy the helper contract accordingly.

#### Lines of Code

[`airdrop.fc#L86-102-L521`](https://github.com/Gusarich/airdrop/blob/e1b1a8e544fb0d68eaeed9a93210ffca045917b7/contracts/airdrop.fc#L86C1-L102C6)

```c++
        elseif (context::op == op::process_claim) {
        cell proof_cell = in_msg_body~load_ref();
        int index = in_msg_body~load_uint(256);

        (slice cs, int exotic?) = proof_cell.begin_parse_exotic();
        throw_unless(42, exotic?);
        throw_unless(43, cs~load_uint(8) == 3);
        throw_unless(44, data::merkle_root == cs~load_uint(256));


        cell dict = cs~load_ref();
        (slice entry, int found?) = dict.udict_get?(256, index);
        throw_unless(45, found?);

        throw_unless(error::wrong_sender, equal_slices(context::sender, helper_address(helper_stateinit(proof_cell.cell_hash(), index))));

        send_tokens(entry~load_msg_addr(), entry~load_coins());
    }       
```

#### Recommendation
Implement a correct proof validation:
- traverse the merkle path usin the supplied leaf and sibling hashes.
- recompute the merkle root.
- reject the proof if the recomputed root does not match `data::merkle_root`.

Use this logic to validate rather than a simple check of:
```c++
throw_unless(44, data::merkle_root == cs~load_uint(256));
```

### <br/> [H-02] Front-running is possible, allowing an attacker to burn all the owner's tokens, thereby grieving the airdrop.

#### Details 
On deployment, the jetton wallet of the contract is set optionally, and when called to set the jetton
This allows the admin to deploy the airdrop and send tokens to the airdrop(creating for the airdrop contract a jetton contract for the tokens to be distributed), which it would further distribute to users on calls to claim from the helpers, the issue here comes from the idea that on calling the contract with `op == op::deploy` sets the jetton wallet which it would make calls to in order to distribute token as specified by the sender.
```c++
       if (context::op == op::deploy) {
        throw_unless(error::already_deployed, data::jetton_wallet.preload_uint(2) == 0);
        data::jetton_wallet = in_msg_body~load_msg_addr();
        save_data();
    }
```
If the admin opts in for later calls where `op==deploy`, an attacker can send a call first to the contract to set the jetton wallet as any arbitrary token, causing calls to claim to send valueless tokens to users, and all the valid airdrop tokens owned by the airdrop.fc contract instance will be lost forever.

## Attack path
- Owner wants to airdrop 1,000,000 USDC tokens to users.
- He deploys the airdrop contract without setting the jetton wallet.
- He later sends 1,000,000 USDC to the airdrop contract address.
- This creates a jetton wallet that can only be called by the airdrop contract.
- Now the owner wants to set the jetton wallet for the airdrop.fc
- An attacker, seeing that the jetton wallet has been created for the airdrop, can grieve the airdrop by:
- sending a call to the airdrop contract with `op == deploy` knowing the admin will soon call it.
- The attack crafts a message to set the jetton wallet that the airdrop contract will call to a valueless jetton token.
- This can even be made to any address, and since the jetton wallet being set after cannot be changed, the calls to claim will send messages to the incorrect jetton wallet for a valueless token
- The call made by the attacker will pass, and all the USDC owned by the `airdrop.fc` instance, will be lost forever.

Allows setting to an incorrect jetton if the admin has not set it yet. Anyone can make a first call to set the jetton to an incorrect address, where all the value in the real jetton wallet address will be stuck as it requires the `airdrop.fc` instance to call it.

                    
#### Lines of Code

[`airdrop.fc#L80-L84`](https://github.com/Gusarich/airdrop/blob/e1b1a8e544fb0d68eaeed9a93210ffca045917b7/contracts/airdrop.fc#L80C1-L84C6)

```c++
    if (context::op == op::deploy) {
        throw_unless(error::already_deployed, data::jetton_wallet.preload_uint(2) == 0);
        data::jetton_wallet = in_msg_body~load_msg_addr();
        save_data();
    }
```

#### Recommendation

Set the admin during contract creation and ensure only him can make a call where `op == deploy()`, unlike the old code where the admin is set to the first person who makes the call.


### <br/> [M-01] Airdrop helper doesn't handle bounced messages, leading to loss of funds if the messages for claim bounce back for any reason.

#### Details 

The Airdrop helper ensures for gas efficiency and security ensuring a user can only claim once with a given proof, however it sends a bonceable message to the `airdrop.fc` contract, but it has no way to handle bounced msgs and if messages bounced for any reason since the helper has already set the state to claim, the user will never be able to claim his/her airdrop again.
```c++
  slice ds = get_data().begin_parse();
    throw_if(error::already_claimed, ds~load_int(1));
    set_claimed()
```

#### Lines of Code

[`airdrop_helper.fc#L28-L40`](https://github.com/Gusarich/airdrop/blob/e1b1a8e544fb0d68eaeed9a93210ffca045917b7/contracts/airdrop_helper.fc#L28C1-L40C2)

```c++
       send_raw_message(begin_cell()
        .store_uint(0x10, 6)
        .store_slice(airdrop)
        .store_coins(0)
        .store_uint(1, 107)
        .store_ref(begin_cell()
            .store_uint(op::process_claim, 32)
            .store_uint(query_id, 64)
            .store_ref(proof)
            .store_uint(index, 256)
        .end_cell())
    .end_cell(), 128);
}
```

#### Recommendation

Handle bounced msgs properly to ensure funds aren't lost when the msgs sent bounce back.


