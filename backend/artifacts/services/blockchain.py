
import json
import os
from pathlib import Path

from django.conf import settings
from web3 import Web3


def validate_id(value, field_name):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer.")


def validate_address(address):
    if not isinstance(address, str) or not Web3.is_address(address):
        raise ValueError("Invalid wallet address.")
    return Web3.to_checksum_address(address)


def validate_hash(file_hash):
    if not isinstance(file_hash, str):
        raise ValueError("File hash must be a hexadecimal string.")

    try:
        hash_bytes = Web3.to_bytes(hexstr=file_hash)
    except (ValueError, TypeError):
        raise ValueError("Invalid file hash.")

    if len(hash_bytes) != 32:
        raise ValueError("File hash must be exactly 32 bytes.")

    return hash_bytes


def get_web3():
    rpc_url = os.getenv("GANACHE_RPC_URL", "http://127.0.0.1:7545")
    web3 = Web3(Web3.HTTPProvider(rpc_url))

    if not web3.is_connected():
        raise ConnectionError("Unable to connect to Ganache.")

    return web3


def get_registry_contract():
    web3 = get_web3()

    contract_address = os.getenv("NETCOLLAB_CONTRACT_ADDRESS")
    if not contract_address or not Web3.is_address(contract_address):
        raise ValueError("A valid contract address is not configured.")

    abi_path = (
        Path(settings.BASE_DIR).parent
        / "blockchain"
        / "exports"
        / "NetCollabRegistry.json"
    )

    if not abi_path.exists():
        raise FileNotFoundError(f"Contract ABI not found: {abi_path}")

    with open(abi_path, "r", encoding="utf-8") as file:
        contract_data = json.load(file)

    contract = web3.eth.contract(
        address=Web3.to_checksum_address(contract_address),
        abi=contract_data["abi"],
    )

    return web3, contract


def send_transaction(contract_function, gas_limit=350000):
    web3, _ = get_registry_contract()

    private_key = os.getenv("BLOCKCHAIN_REGISTRAR_PRIVATE_KEY")
    if not private_key:
        raise ValueError("Blockchain registrar private key is not configured.")

    account = web3.eth.account.from_key(private_key)

    transaction = contract_function.build_transaction({
        "from": account.address,
        "nonce": web3.eth.get_transaction_count(account.address, "pending"),
        "chainId": web3.eth.chain_id,
        "gas": gas_limit,
        "gasPrice": web3.eth.gas_price,
    })

    signed_transaction = account.sign_transaction(transaction)
    tx_hash = web3.eth.send_raw_transaction(signed_transaction.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    if receipt.status != 1:
        raise RuntimeError("Blockchain transaction failed.")

    return {
        "transaction_hash": tx_hash.hex(),
        "block_number": receipt.blockNumber,
        "contract_address": contract_function.address,
    }


def register_artifact(artifact_id, version_number, project_id,
                      contributor_address, file_hash):
    validate_id(artifact_id, "Artifact ID")
    validate_id(version_number, "Version number")
    validate_id(project_id, "Project ID")

    contributor_address = validate_address(contributor_address)
    file_hash = validate_hash(file_hash)

    _, contract = get_registry_contract()

    return send_transaction(
        contract.functions.registerArtifact(
            artifact_id,
            version_number,
            project_id,
            contributor_address,
            file_hash,
        )
    )


def verify_artifact(artifact_id, version_number, file_hash):
    validate_id(artifact_id, "Artifact ID")
    validate_id(version_number, "Version number")
    file_hash = validate_hash(file_hash)

    _, contract = get_registry_contract()

    verified = contract.functions.verifyArtifact(
        artifact_id,
        version_number,
        file_hash,
    ).call()

    return {
        "artifact_id": artifact_id,
        "version_number": version_number,
        "verified": verified,
        "contract_address": contract.address,
    }


def get_artifact_details(artifact_id, version_number):
    validate_id(artifact_id, "Artifact ID")
    validate_id(version_number, "Version number")

    _, contract = get_registry_contract()

    artifact = contract.functions.getArtifactDetails(
        artifact_id,
        version_number,
    ).call()

    if not artifact[6]:
        return None

    return {
        "artifact_id": artifact[0],
        "version_number": artifact[1],
        "project_id": artifact[2],
        "contributor": artifact[3],
        "file_hash": Web3.to_hex(artifact[4]),
        "timestamp": artifact[5],
        "exists": artifact[6],
    }
