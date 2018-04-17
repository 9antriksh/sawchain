import sawtooth_sdk

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
context = create_context('secp256k1')
private_key = context.new_random_private_key()
signer = CryptoFactory(context).new_signer(private_key)
import cbor

payload = {
    'Verb': 'set',
    'Name': 'Tuna Box',
    'Value': 11034}
payload1 = {
    'Verb': 'set',
    'Name': 'Refrigerator number',
    'Value': 1001254}
payload2 = {
    'Verb': 'set',
    'Name': 'Tempature',
    'Value': 18}
payload3 = {
    'Verb': 'set',
    'Name': 'Locationlat',
    'Value':78 }
payload4 = {
    'Verb': 'set',
    'Name': 'Locationlong',
    'Value':89 }


payload_bytes = cbor.dumps(payload)
payload_bytes1 = cbor.dumps(payload1)
payload_bytes2 = cbor.dumps(payload2)
payload_bytes3 = cbor.dumps(payload3)
payload_bytes4 = cbor.dumps(payload4)
from hashlib import sha512
hash  = sha512('intkey'.encode('utf-8')).hexdigest()[0:6] + sha512(payload['Name'].encode('utf-8')).hexdigest()[-64:]

from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader

txn_header_bytes = TransactionHeader(
    family_name='intkey',
    family_version='1.0',
    inputs=[hash],
    outputs=[hash],
    signer_public_key=signer.get_public_key().as_hex(),
    # In this example, we're signing the batch with the same private key,
    # but the batch can be signed by another party, in which case, the
    # public key will need to be associated with that key.
    batcher_public_key=signer.get_public_key().as_hex(),
    # In this example, there are no dependencies.  This list should include
    # an previous transaction header signatures that must be applied for
    # this transaction to successfully commit.
    # For example,
    # dependencies=['540a6803971d1880ec73a96cb97815a95d374cbad5d865925e5aa0432fcf1931539afe10310c122c5eaae15df61236079abbf4f258889359c4d175516934484a'],
    dependencies=[],
    payload_sha512=sha512(payload_bytes).hexdigest()
).SerializeToString()
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction

signature = signer.sign(txn_header_bytes)

txn = Transaction(
    header=txn_header_bytes,
    header_signature=signature,
    payload = payload_bytes
)
hash1  = sha512('intkey'.encode('utf-8')).hexdigest()[0:6] + sha512(payload1['Name'].encode('utf-8')).hexdigest()[-64:]
txn_header_bytes1 = TransactionHeader(
    family_name='intkey',
    family_version='1.0',
    inputs=[hash1],
    outputs=[hash1],
    signer_public_key=signer.get_public_key().as_hex(),
    # In this example, we're signing the batch with the same private key,
    # but the batch can be signed by another party, in which case, the
    # public key will need to be associated with that key.
    batcher_public_key=signer.get_public_key().as_hex(),
    # In this example, there are no dependencies.  This list should include
    # an previous transaction header signatures that must be applied for
    # this transaction to successfully commit.
    # For example,
    # dependencies=['540a6803971d1880ec73a96cb97815a95d374cbad5d865925e5aa0432fcf1931539afe10310c122c5eaae15df61236079abbf4f258889359c4d175516934484a'],
    dependencies=[],
    payload_sha512=sha512(payload_bytes1).hexdigest()
).SerializeToString()
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction

signature1 = signer.sign(txn_header_bytes1)

txn1 = Transaction(
    header=txn_header_bytes1,
    header_signature=signature1,
    payload = payload_bytes1
)
hash2  = sha512('intkey'.encode('utf-8')).hexdigest()[0:6] + sha512(payload2['Name'].encode('utf-8')).hexdigest()[-64:]
txn_header_bytes2 = TransactionHeader(
    family_name='intkey',
    family_version='1.0',
    inputs=[hash2],
    outputs=[hash2],
    signer_public_key=signer.get_public_key().as_hex(),
    # In this example, we're signing the batch with the same private key,
    # but the batch can be signed by another party, in which case, the
    # public key will need to be associated with that key.
    batcher_public_key=signer.get_public_key().as_hex(),
    # In this example, there are no dependencies.  This list should include
    # an previous transaction header signatures that must be applied for
    # this transaction to successfully commit.
    # For example,
    # dependencies=['540a6803971d1880ec73a96cb97815a95d374cbad5d865925e5aa0432fcf1931539afe10310c122c5eaae15df61236079abbf4f258889359c4d175516934484a'],
    dependencies=[],
    payload_sha512=sha512(payload_bytes2).hexdigest()
).SerializeToString()
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction

signature2 = signer.sign(txn_header_bytes2)

txn2 = Transaction(
    header=txn_header_bytes2,
    header_signature=signature2,
    payload = payload_bytes2
)
hash3  = sha512('intkey'.encode('utf-8')).hexdigest()[0:6] + sha512(payload3['Name'].encode('utf-8')).hexdigest()[-64:]
txn_header_bytes3 = TransactionHeader(
    family_name='intkey',
    family_version='1.0',
    inputs=[hash3],
    outputs=[hash3],
    signer_public_key=signer.get_public_key().as_hex(),
    # In this example, we're signing the batch with the same private key,
    # but the batch can be signed by another party, in which case, the
    # public key will need to be associated with that key.
    batcher_public_key=signer.get_public_key().as_hex(),
    # In this example, there are no dependencies.  This list should include
    # an previous transaction header signatures that must be applied for
    # this transaction to successfully commit.
    # For example,
    # dependencies=['540a6803971d1880ec73a96cb97815a95d374cbad5d865925e5aa0432fcf1931539afe10310c122c5eaae15df61236079abbf4f258889359c4d175516934484a'],
    dependencies=[],
    payload_sha512=sha512(payload_bytes3).hexdigest()
).SerializeToString()
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction

signature3 = signer.sign(txn_header_bytes3)

txn3 = Transaction(
    header=txn_header_bytes3,
    header_signature=signature3,
    payload = payload_bytes3
)
hash4  = sha512('intkey'.encode('utf-8')).hexdigest()[0:6] + sha512(payload4['Name'].encode('utf-8')).hexdigest()[-64:]
txn_header_bytes4 = TransactionHeader(
    family_name='intkey',
    family_version='1.0',
    inputs=[hash4],
    outputs=[hash4],
    signer_public_key=signer.get_public_key().as_hex(),
    # In this example, we're signing the batch with the same private key,
    # but the batch can be signed by another party, in which case, the
    # public key will need to be associated with that key.
    batcher_public_key=signer.get_public_key().as_hex(),
    # In this example, there are no dependencies.  This list should include
    # an previous transaction header signatures that must be applied for
    # this transaction to successfully commit.
    # For example,
    # dependencies=['540a6803971d1880ec73a96cb97815a95d374cbad5d865925e5aa0432fcf1931539afe10310c122c5eaae15df61236079abbf4f258889359c4d175516934484a'],
    dependencies=[],
    payload_sha512=sha512(payload_bytes4).hexdigest()
).SerializeToString()
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction

signature4 = signer.sign(txn_header_bytes4)

txn4 = Transaction(
    header=txn_header_bytes4,
    header_signature=signature4,
    payload = payload_bytes4
)
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader

txns = [txn,txn1,txn3,txn4]

batch_header_bytes = BatchHeader(
    signer_public_key=signer.get_public_key().as_hex(),
    transaction_ids=[txn.header_signature for txn in txns],
).SerializeToString()
from sawtooth_sdk.protobuf.batch_pb2 import Batch

signature = signer.sign(batch_header_bytes)

batch = Batch(
    header=batch_header_bytes,
    header_signature=signature,
    transactions=txns
)
from sawtooth_sdk.protobuf.batch_pb2 import BatchList

batch_list_bytes = BatchList(batches=[batch]).SerializeToString()
import urllib.request
from urllib.error import HTTPError

try:
    request = urllib.request.Request(
        'http://172.30.108.255:8008/batches',
        batch_list_bytes,
        method='POST',
        headers={'Content-Type': 'application/octet-stream'})
    response = urllib.request.urlopen(request)

except HTTPError as e:
    response = e.file

output = open('intkey.batches', 'wb')
output.write(batch_list_bytes)

