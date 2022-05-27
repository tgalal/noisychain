# NZYCHN

## Setup

Install dependencies

```
pip install -r requirements.txt
```

Set RPC URL as env variable:

```
# Example
export W3RPC="http://192.168.178.11:7545"
```

## N-Based messaging

```
# Initiator sends a message
python noisychain-cli.py send \
    --protocol N \
    --pubkey 032c80af6ce6dbce65f0efd3f441dd2a8a5528a29d4d27483895a6bc17e1d5c240

# > Waiting for 0x4f9ACbE0d608bCe78cD0703627C69b117E4511FC to have 0.0025148 ETH,

#  Fund the ephemeral account
python noisychain-cli.py fund \
   --key data/alice.bin --key-format hex \
   --address 0x4f9ACbE0d608bCe78cD0703627C69b117E4511FC \
   --method internal \
   --value 2576000000000000 -d

# Responder receives message
python noisychain-cli.py recv \
   --protocol N \
   --key data/bob.bin --key-format hex
```

## K-Based Messaging

```
# Initiator sends a message, will automatically fund the ephemeral account for
# using the initiator's account for simplicity.
python noisychain-cli.py send \
    --protocol K \
    --key data/alice.bin --key-format hex \
    --pubkey 032c80af6ce6dbce65f0efd3f441dd2a8a5528a29d4d27483895a6bc17e1d5c240

# Responder receives message
python noisychain-cli.py recv \
   --protocol K \
   --key data/bob.bin --key-format hex \
   --pubkey 03c52cf41d23397d6312cbcf8deba4b1ad7b68635de4d9d967c86e0496e3f4d1c
```

## X-Based Messaging

```
# Initiator sends a message, will automatically fund the ephemeral account for
# using the initiator's account for simplicity.
python noisychain-cli.py send \
    --protocol X \
    --key data/alice.bin --key-format hex \
    --pubkey 032c80af6ce6dbce65f0efd3f441dd2a8a5528a29d4d27483895a6bc17e1d5c240

# Responder receives message
python noisychain-cli.py recv \
   --protocol X \
   --key data/bob.bin --key-format hex
```

## KK-Based using channels

Command line options are not available, but unit tests. Running those tests
requires updating the keys used. Currently they're hardcoded in the tests.

```
python -u -m pytest -k tests/test_channelstate.py -s
python -u -m pytest -k tests/test_nk_protocol -s
python -u -m pytest -k tests/test_kk_protocol -s
```

