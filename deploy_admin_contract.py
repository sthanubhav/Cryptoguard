from web3 import Web3, HTTPProvider

def deploy_contract(contract_interface, private_key, node_url, sender_address):
    web3 = Web3(HTTPProvider(node_url))

    # Convert the private key to bytes
    private_key_bytes = bytes.fromhex(private_key)

    # Load contract ABI and bytecode
    abi = contract_interface['abi']
    bytecode = contract_interface['bin']

    # Create contract instance
    contract = web3.eth.contract(abi=abi, bytecode=bytecode)

    # Get the nonce for the sender address
    nonce = web3.eth.get_transaction_count(sender_address)

    # Build transaction dictionary
    tx_dict = {
        'chainId': 1,
        'gas': 2000000,
        'gasPrice': web3.to_wei('50', 'gwei'),
        'nonce': nonce,
        'from': sender_address
    }

    # Sign transaction
    signed_tx = web3.eth.account.sign_transaction(tx_dict, private_key_bytes)

    # Send raw transaction
    tx_receipt = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_receipt)

    return tx_receipt.contractAddress


# Example usage
if __name__ == "__main__":
    # Example deployment parameters
    contract_interface = {'abi': [{'anonymous': False, 'inputs': [{'indexed': True, 'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}, {'indexed': False, 'internalType': 'uint256', 'name': 'timestamp', 'type': 'uint256'}, {'indexed': True, 'internalType': 'address', 'name': 'user', 'type': 'address'}, {'indexed': False, 'internalType': 'uint256', 'name': 'level', 'type': 'uint256'}, {'indexed': False, 'internalType': 'string', 'name': 'message', 'type': 'string'}, {'indexed': False, 'internalType': 'string', 'name': 'traceback', 'type': 'string'}], 'name': 'LogAdded', 'type': 'event'}, {'anonymous': False, 'inputs': [{'indexed': True, 'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}, {'indexed': True, 'internalType': 'address', 'name': 'deleter', 'type': 'address'}, {'indexed': False, 'internalType': 'uint256', 'name': 'deletedTimestamp', 'type': 'uint256'}, {'indexed': False, 'internalType': 'uint256', 'name': 'level', 'type': 'uint256'}, {'indexed': False, 'internalType': 'string', 'name': 'message', 'type': 'string'}, {'indexed': False, 'internalType': 'string', 'name': 'traceback', 'type': 'string'}], 'name': 'LogDeleted', 'type': 'event'}, {'anonymous': False, 'inputs': [{'indexed': True, 'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}, {'indexed': True, 'internalType': 'address', 'name': 'editor', 'type': 'address'}, {'indexed': False, 'internalType': 'string', 'name': 'oldMessage', 'type': 'string'}, {'indexed': False, 'internalType': 'string', 'name': 'newMessage', 'type': 'string'}], 'name': 'LogEdited', 'type': 'event'}, {'inputs': [{'internalType': 'uint256', 'name': '_level', 'type': 'uint256'}, {'internalType': 'string', 'name': '_message', 'type': 'string'}, {'internalType': 'string', 'name': '_traceback', 'type': 'string'}], 'name': 'addLog', 'outputs': [], 'stateMutability': 'nonpayable', 'type': 'function'}, {'inputs': [{'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}], 'name': 'deleteLog', 'outputs': [], 'stateMutability': 'nonpayable', 'type': 'function'}, {'inputs': [{'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}, {'internalType': 'string', 'name': 'newMessage', 'type': 'string'}], 'name': 'editLog', 'outputs': [], 'stateMutability': 'nonpayable', 'type': 'function'}, {'inputs': [], 'name': 'getAllLogs', 'outputs': [{'components': [{'internalType': 'uint256', 'name': 'timestamp', 'type': 'uint256'}, {'internalType': 'address', 'name': 'user', 'type': 'address'}, {'internalType': 'uint256', 'name': 'level', 'type': 'uint256'}, {'internalType': 'string', 'name': 'message', 'type': 'string'}, {'internalType': 'string', 'name': 'traceback', 'type': 'string'}], 'internalType': 'struct AdminLogger.Log[]', 'name': '', 'type': 'tuple[]'}], 'stateMutability': 'view', 'type': 'function'}, {'inputs': [{'internalType': 'uint256', 'name': 'index', 'type': 'uint256'}], 'name': 'getLog', 'outputs': [{'internalType': 'uint256', 'name': 'timestamp', 'type': 'uint256'}, {'internalType': 'address', 'name': 'user', 'type': 'address'}, {'internalType': 'uint256', 'name': 'level', 'type': 'uint256'}, {'internalType': 'string', 'name': 'message', 'type': 'string'}, {'internalType': 'string', 'name': 'traceback', 'type': 'string'}], 'stateMutability': 'view', 'type': 'function'}, {'inputs': [], 'name': 'getLogsCount', 'outputs': [{'internalType': 'uint256', 'name': '', 'type': 'uint256'}], 'stateMutability': 'view', 'type': 'function'}, {'inputs': [{'internalType': 'uint256', 'name': '', 'type': 'uint256'}], 'name': 'logs', 'outputs': [{'internalType': 'uint256', 'name': 'timestamp', 'type': 'uint256'}, {'internalType': 'address', 'name': 'user', 'type': 'address'}, {'internalType': 'uint256', 'name': 'level', 'type': 'uint256'}, {'internalType': 'string', 'name': 'message', 'type': 'string'}, {'internalType': 'string', 'name': 'traceback', 'type': 'string'}], 'stateMutability': 'view', 'type': 'function'}], 'bin': '608060405234801561001057600080fd5b5061133a806100206000396000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c8063890bc8fb1161005b578063890bc8fb146100d7578063cc9e300f146100ea578063e581329b146100ff578063e79899bd146101145761007d565b80633206b2c6146100825780633227dab1146100af5780637e4fd411146100c4575b600080fd5b610095610090366004610f57565b610127565b6040516100a6959493929190611209565b60405180910390f35b6100c26100bd366004610fb4565b610329565b005b6100c26100d2366004610f6f565b6104a2565b6100c26100e5366004610f57565b610660565b6100f2610a6f565b6040516100a69190611200565b610107610a75565b6040516100a69190611069565b610095610122366004610f57565b610c23565b6000806000606080600080549050861061015c5760405162461bcd60e51b81526004016101539061118c565b60405180910390fd5b600080878154811061017e57634e487b7160e01b600052603260045260246000fd5b90600052602060002090600502016040518060a0016040529081600082015481526020016001820160009054906101000a90046001600160a01b03166001600160a01b03166001600160a01b03168152602001600282015481526020016003820180546101ea906112b3565b80601f0160208091040260200160405190810160405280929190818152602001828054610216906112b3565b80156102635780601f1061023857610100808354040283529160200191610263565b820191906000526020600020905b81548152906001019060200180831161024657829003601f168201915b5050505050815260200160048201805461027c906112b3565b80601f01602080910402602001604051908101604052809291908181526020018280546102a8906112b3565b80156102f55780601f106102ca576101008083540402835291602001916102f5565b820191906000526020600020905b8154815290600101906020018083116102d857829003601f168201915b5050509190925250508151602083015160408401516060850151608090950151929c919b5099509297509550909350505050565b6040805160a081018252428152336020808301918252928201868152606083018681526080840186905260008054600181018255908052845160059091027f290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563810191825593517f290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e564850180546001600160a01b03929092166001600160a01b031990921691909117905591517f290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56584015551805193949193610430937f290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56601929190910190610d83565b506080820151805161044c916004840191602090910190610d83565b505060005433915061046090600190611290565b7f4523dea6a2905bbfd2a10e7765fdc6f8f7b6bd394c8c21124ac3ae708de1e955428686866040516104959493929190611254565b60405180910390a3505050565b60005482106104c35760405162461bcd60e51b81526004016101539061118c565b600082815481106104e457634e487b7160e01b600052603260045260246000fd5b60009182526020909120600590910201600101546001600160a01b0316331461051f5760405162461bcd60e51b815260040161015390611147565b600080838154811061054157634e487b7160e01b600052603260045260246000fd5b9060005260206000209060050201600301805461055d906112b3565b80601f0160208091040260200160405190810160405280929190818152602001828054610589906112b3565b80156105d65780601f106105ab576101008083540402835291602001916105d6565b820191906000526020600020905b8154815290600101906020018083116105b957829003601f168201915b5050505050905081600084815481106105ff57634e487b7160e01b600052603260045260246000fd5b90600052602060002090600502016003019080519060200190610623929190610d83565b50336001600160a01b0316837f16d52920227e9ab2f9073fdb47caa191ffbbeecb1ae6af8e23022727d13d61fc8385604051610495929190611119565b60005481106106815760405162461bcd60e51b81526004016101539061118c565b600081815481106106a257634e487b7160e01b600052603260045260246000fd5b60009182526020909120600590910201600101546001600160a01b031633146106dd5760405162461bcd60e51b8152600401610153906111b9565b60008082815481106106ff57634e487b7160e01b600052603260045260246000fd5b9060005260206000209060050201600001549050600080838154811061073557634e487b7160e01b600052603260045260246000fd5b9060005260206000209060050201600201549050600080848154811061076b57634e487b7160e01b600052603260045260246000fd5b90600052602060002090600502016003018054610787906112b3565b80601f01602080910402602001604051908101604052809291908181526020018280546107b3906112b3565b80156108005780601f106107d557610100808354040283529160200191610800565b820191906000526020600020905b8154815290600101906020018083116107e357829003601f168201915b50505050509050600080858154811061082957634e487b7160e01b600052603260045260246000fd5b90600052602060002090600502016004018054610845906112b3565b80601f0160208091040260200160405190810160405280929190818152602001828054610871906112b3565b80156108be5780601f10610893576101008083540402835291602001916108be565b820191906000526020600020905b8154815290600101906020018083116108a157829003601f168201915b50506000805494955033949093506108da925060019150611290565b815481106108f857634e487b7160e01b600052603260045260246000fd5b90600052602060002090600502016000878154811061092757634e487b7160e01b600052603260045260246000fd5b60009182526020909120825460059092020190815560018083015490820180546001600160a01b0319166001600160a01b03909216919091179055600280830154908201556003808301805491830191610980906112b3565b61098b929190610e07565b5060048201816004019080546109a0906112b3565b6109ab929190610e07565b5090505060008054806109ce57634e487b7160e01b600052603160045260246000fd5b6000828152602081206005600019909301928302018181556001810180546001600160a01b03191690556002810182905590610a0d6003830182610e82565b610a1b600483016000610e82565b50509055806001600160a01b0316867ffa3b748a088c835b1c4cd15e5a1f0e51df1ebdc9d1d636a1dd2f49d9c3bcf6d987878787604051610a5f9493929190611254565b60405180910390a3505050505050565b60005490565b60606000805480602002602001604051908101604052809291908181526020016000905b82821015610c1a5760008481526020908190206040805160a081018252600586029092018054835260018101546001600160a01b031693830193909352600283015490820152600382018054919291606084019190610af7906112b3565b80601f0160208091040260200160405190810160405280929190818152602001828054610b23906112b3565b8015610b705780601f10610b4557610100808354040283529160200191610b70565b820191906000526020600020905b815481529060010190602001808311610b5357829003601f168201915b50505050508152602001600482018054610b89906112b3565b80601f0160208091040260200160405190810160405280929190818152602001828054610bb5906112b3565b8015610c025780601f10610bd757610100808354040283529160200191610c02565b820191906000526020600020905b815481529060010190602001808311610be557829003601f168201915b50505050508152505081526020019060010190610a99565b50505050905090565b60008181548110610c3357600080fd5b600091825260209091206005909102018054600182015460028301546003840180549395506001600160a01b03909216939092909190610c72906112b3565b80601f0160208091040260200160405190810160405280929190818152602001828054610c9e906112b3565b8015610ceb5780601f10610cc057610100808354040283529160200191610ceb565b820191906000526020600020905b815481529060010190602001808311610cce57829003601f168201915b505050505090806004018054610d00906112b3565b80601f0160208091040260200160405190810160405280929190818152602001828054610d2c906112b3565b8015610d795780601f10610d4e57610100808354040283529160200191610d79565b820191906000526020600020905b815481529060010190602001808311610d5c57829003601f168201915b5050505050905085565b828054610d8f906112b3565b90600052602060002090601f016020900481019282610db15760008555610df7565b82601f10610dca57805160ff1916838001178555610df7565b82800160010185558215610df7579182015b82811115610df7578251825591602001919060010190610ddc565b50610e03929150610ec1565b5090565b828054610e13906112b3565b90600052602060002090601f016020900481019282610e355760008555610df7565b82601f10610e465780548555610df7565b82800160010185558215610df757600052602060002091601f016020900482015b82811115610df7578254825591600101919060010190610e67565b508054610e8e906112b3565b6000825580601f10610ea05750610ebe565b601f016020900490600052602060002090810190610ebe9190610ec1565b50565b5b80821115610e035760008155600101610ec2565b600082601f830112610ee6578081fd5b813567ffffffffffffffff80821115610f0157610f016112ee565b604051601f8301601f191681016020018281118282101715610f2557610f256112ee565b604052828152848301602001861015610f3c578384fd5b82602086016020830137918201602001929092529392505050565b600060208284031215610f68578081fd5b5035919050565b60008060408385031215610f81578081fd5b82359150602083013567ffffffffffffffff811115610f9e578182fd5b610faa85828601610ed6565b9150509250929050565b600080600060608486031215610fc8578081fd5b83359250602084013567ffffffffffffffff80821115610fe6578283fd5b610ff287838801610ed6565b93506040860135915080821115611007578283fd5b5061101486828701610ed6565b9150509250925092565b60008151808452815b8181101561104357602081850181015186830182015201611027565b818111156110545782602083870101525b50601f01601f19169290920160200192915050565b60208082528251828201819052600091906040908185019080840286018301878501865b8381101561110b57888303603f19018552815180518452878101516001600160a01b031688850152868101518785015260608082015160a082870181905291906110d98388018261101e565b92505050608080830151925085820381870152506110f7818361101e565b96890196945050509086019060010161108d565b509098975050505050505050565b60006040825261112c604083018561101e565b828103602084015261113e818561101e565b95945050505050565b60208082526025908201527f4f6e6c7920746865206c6f672063726561746f722063616e206564697420746860408201526465206c6f6760d81b606082015260800190565b602080825260139082015272496e646578206f7574206f6620626f756e647360681b604082015260600190565b60208082526027908201527f4f6e6c7920746865206c6f672063726561746f722063616e2064656c65746520604082015266746865206c6f6760c81b606082015260800190565b90815260200190565b600086825260018060a01b038616602083015284604083015260a0606083015261123660a083018561101e565b8281036080840152611248818561101e565b98975050505050505050565b600085825284602083015260806040830152611273608083018561101e565b8281036060840152611285818561101e565b979650505050505050565b6000828210156112ae57634e487b7160e01b81526011600452602481fd5b500390565b6002810460018216806112c757607f821691505b602082108114156112e857634e487b7160e01b600052602260045260246000fd5b50919050565b634e487b7160e01b600052604160045260246000fdfea2646970667358221220a2f3a8fcc5bb7da23b5196d0342756f45dc090d258870b88f04a29409cf381cf64736f6c63430008000033'}
    private_key = '4cfdd494d262b8e3348a30fdded2b87adb3f81b67b0357dfb44db75fc1c3a2cd'
    node_url = 'http://127.0.0.1:7545'

    sender_address = '0x31A5826B4cF87fB437CFBa47504959F49F91A051'

    contract_address = deploy_contract(contract_interface, private_key, node_url, sender_address)
    print("Contract deployed at address:", contract_address)
