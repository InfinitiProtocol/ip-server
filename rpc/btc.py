from sys import exit, argv
from os import system
from pycoin.services.blockchain_info import spendables_for_address
from pycoin.tx import script, Tx
from pycoin.tx.tx_utils import sign_tx
from pycoin.tx.TxOut import TxOut, standard_tx_out_script
from binascii import hexlify

# Borrowed from 
#	https://gist.githubusercontent.com/harding/d34b581d8cfbb8919812/raw/send-op-return.py
# 	https://gist.githubusercontent.com/harding/983b9aa19ff7cfb8ec80/raw/retrieve-op-return.py

## This is the address and key you generated before
bitcoin_address = "ADDRESS"
bitcoin_private_key = "PRIVATE_KEY"

## The fee that will be given to the miner in bitcoin
bitcoin_fee = 10000 # In satoshis

## Get the message
if(len(argv) is not 2):
    exit("usage: python3 send-op-return.py \"MESSAGE\"")
raw_message = argv[1]
if(len(raw_message) > 80):
    exit("Message must be 80 characters or less")
message = hexlify(raw_message.encode()).decode('utf8')

## Get the spendable outputs we are going to use to pay the fee
spendables = spendables_for_address(bitcoin_address)
bitcoin_sum = sum(spendable.coin_value for spendable in spendables)
if(bitcoin_sum < bitcoin_fee):
    exit("Not enough satoshis to cover the fee. found: {sum} need: {fee}"
    .format(sum=bitcoin_sum,fee=bitcoin_fee))

## Create the inputs we are going to use
inputs = [spendable.tx_in() for spendable in spendables]

## If we will have change left over create an output to send it back
outputs = []
if (bitcoin_sum > bitcoin_fee):
    change_output_script = standard_tx_out_script(bitcoin_address)
    outputs.append(TxOut(bitcoin_sum - bitcoin_fee, change_output_script))

## Build the OP_RETURN output with our message
op_return_output_script = script.tools.compile("OP_RETURN %s" % message)
outputs.append(TxOut(0, op_return_output_script))

## Create the transaction and sign it with the private key
tx = Tx(version=1, txs_in=inputs, txs_out=outputs)
tx.set_unspents(spendables)
signed_tx = sign_tx(tx, wifs=[bitcoin_private_key])

## Send the signed transaction to the network through bitcoind
## Note: that os.system() prints the response for us
system("bitcoin-cli sendrawtransaction %s" % tx.as_hex())