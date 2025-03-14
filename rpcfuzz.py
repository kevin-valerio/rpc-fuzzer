#!/usr/bin/env python

from websocket import create_connection
import json
import string
import random
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


class AdaptiveRPCFuzzer:
    def __init__(self, ws_url: str):
        self.ws_url = ws_url
        self.socket = None
        self.method_params_map = {}
        self.request_id = 1
        self.success_responses = {}
        self.custom_generators = {
            "PrefixedStorageKey": self.generate_prefixed_storage_key,
            "StorageKey": self.generate_storage_key,
            "u32": self.generate_u32,
            "u64": self.generate_u64,
            "Hash": self.generate_hash,
            "BlockHash": self.generate_block_hash,
            "AccountId": self.generate_account_id,
            "Address": self.generate_address,
            "Bytes": self.generate_bytes,
            "String": self.generate_string,
            "bool": self.generate_bool,
            "Option": self.generate_option,
            "Vec": self.generate_vec
        }
        self.methods = [
            "account_nextIndex",
            "author_hasKey",
            "author_hasSessionKeys",
            "author_insertKey",
            "author_pendingExtrinsics",
            "author_rotateKeys",
            "author_submitAndWatchExtrinsic",
            "author_submitExtrinsic",
            "author_unwatchExtrinsic",
            "beefy_getFinalizedHead",
            "chain_getBlock",
            "chain_getBlockHash",
            "chain_getFinalisedHead",
            "chain_getFinalizedHead",
            "chain_getHead",
            "chain_getHeader",
            # "chain_getRuntimeVersion",
            "chain_subscribeFinalizedHeads",
            "chain_subscribeNewHead",
            "chain_subscribeNewHeads",
            "chain_unsubscribeFinalizedHeads",
            "chain_unsubscribeNewHead",
            "chain_unsubscribeNewHeads",
            "childstate_getKeys",
            "childstate_getKeysPaged",
            "childstate_getStorage",
            "childstate_getStorageAt",
            "childstate_getStorageHash",
            "childstate_getStorageHashAt",
            "childstate_getStorageSize",
            "childstate_getStorageSizeAt",
            "internal_setLogLevel",
            "mmr_generateProof",
            "mmr_root",
            "mmr_verifyProof",
            "mmr_verifyProofStateless",
            "payment_queryInfo",
            "rpc_methods",
            "state_call",
            "state_getKeysPaged",
            "state_getMetadata",
            "state_getReadProof",
            "state_getRuntimeVersion",
            "state_getStorage",
            "state_getStorageAt",
            "state_getStorageSize",
            "state_queryStorage",
            "state_queryStorageAt",
            "state_subscribeRuntimeVersion",
            "state_subscribeStorage",
            "state_unsubscribeRuntimeVersion",
            "state_unsubscribeStorage",
            "system_accountNextIndex",
            "system_chain",
            "system_chainType",
            "system_health",
            "system_name",
            "system_peers",
            "system_properties",
            "system_version"
        ]
        self.method_param_patterns = {
            "account_nextIndex": ["AccountId"],

            "author_hasKey": ["Bytes", "String"],
            "author_hasSessionKeys": ["Bytes"],
            "author_insertKey": ["String", "String", "Bytes"],
            "author_pendingExtrinsics": [],
            "author_rotateKeys": [],
            "author_submitAndWatchExtrinsic": ["Extrinsic"],
            "author_submitExtrinsic": ["Extrinsic"],
            "author_unwatchExtrinsic": ["ExtrinsicWatchId"],

            "beefy_getFinalizedHead": [],

            "chain_getBlock": ["BlockHash"],
            "chain_getBlockHash": ["u32"],
            "chain_getFinalisedHead": [],
            "chain_getFinalizedHead": [],
            "chain_getHead": [],
            "chain_getHeader": ["BlockHash"],
            "chain_getRuntimeVersion": ["BlockHash"],  
            "chain_subscribeFinalizedHeads": [],
            "chain_subscribeNewHead": [],
            "chain_subscribeNewHeads": [],
            "chain_unsubscribeFinalizedHeads": ["SubscriptionId"],
            "chain_unsubscribeNewHead": ["SubscriptionId"],
            "chain_unsubscribeNewHeads": ["SubscriptionId"],

            "childstate_getKeys": ["PrefixedStorageKey", "StorageKey"],
            "childstate_getKeysPaged": ["PrefixedStorageKey", "StorageKey", "u32"],
            "childstate_getStorage": ["PrefixedStorageKey", "StorageKey"],
            "childstate_getStorageAt": ["PrefixedStorageKey", "StorageKey", "BlockHash"],
            "childstate_getStorageHash": ["PrefixedStorageKey", "StorageKey"],
            "childstate_getStorageHashAt": ["PrefixedStorageKey", "StorageKey", "BlockHash"],
            "childstate_getStorageSize": ["PrefixedStorageKey", "StorageKey"],
            "childstate_getStorageSizeAt": ["PrefixedStorageKey", "StorageKey", "BlockHash"],
            "internal_setLogLevel": ["String", "u32"],
            "mmr_generateProof": ["u64", "BlockHash"],
            "mmr_root": ["BlockHash"],
            "mmr_verifyProof": ["MmrLeaf", "MmrProof"],
            "mmr_verifyProofStateless": ["MmrHash", "MmrProof", "Vec<MmrLeaf>"],
            "payment_queryInfo": ["Extrinsic", "BlockHash"],
            "rpc_methods": [],
            "state_call": ["String", "Bytes", "BlockHash"],
            "state_getKeysPaged": ["StorageKey", "u32"],
            "state_getMetadata": ["BlockHash"],
            "state_getReadProof": ["Vec<StorageKey>", "BlockHash"],
            "state_getRuntimeVersion": ["BlockHash"],
            "state_getStorage": ["StorageKey"],
            "state_getStorageAt": ["StorageKey", "BlockHash"],
            "state_getStorageSize": ["StorageKey", "BlockHash"],
            "state_queryStorage": ["Vec<StorageKey>", "BlockHash", "BlockHash"],
            "state_queryStorageAt": ["Vec<StorageKey>", "BlockHash"],
            "state_subscribeRuntimeVersion": [],
            "state_subscribeStorage": ["Vec<StorageKey>"],
            "state_unsubscribeRuntimeVersion": ["SubscriptionId"],
            "state_unsubscribeStorage": ["SubscriptionId"],

            "system_accountNextIndex": ["AccountId"],
            "system_chain": [],
            "system_chainType": [],
            "system_health": [],
            "system_name": [],
            "system_peers": [],
            "system_properties": [],
            "system_version": []
        }

    def connect(self):
        try:
            self.socket = create_connection(self.ws_url)
            logger.info(f"Connected to {self.ws_url}")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def disconnect(self):
        if self.socket:
            self.socket.close()
            logger.info("Disconnected from WebSocket")

    def generate_hex_string(self, min_length=2, max_length=64):
        length = random.randint(min_length, max_length)
        return "0x" + ''.join(random.choice(string.hexdigits)
                              for _ in range(length))

    def generate_prefixed_storage_key(self):
        prefix = "0x" + ''.join(random.choice(string.hexdigits)
                                for _ in range(8))
        key = self.generate_storage_key()[2:]   
        return prefix + key

    def generate_storage_key(self):
        return "0x" + ''.join(random.choice(string.hexdigits)
                              for _ in range(64))

    def generate_u32(self):
        return random.randint(0, 2**32 - 1)

    def generate_u64(self):
        return random.randint(0, 2**64 - 1)

    def generate_hash(self):
        return "0x" + ''.join(random.choice(string.hexdigits)
                              for _ in range(64))

    def generate_block_hash(self):
        if "chain_getBlockHash" in self.success_responses:
            successful_hashes = [
                resp.get("result") for resp in self.success_responses["chain_getBlockHash"]]
            if successful_hashes:
                return random.choice(successful_hashes)
        return self.generate_hash()

    def generate_account_id(self):
        return "0x" + ''.join(random.choice(string.hexdigits)
                              for _ in range(64))

    def generate_address(self):
        return "0x" + ''.join(random.choice(string.hexdigits)
                              for _ in range(40))

    def generate_bytes(self):
        length = random.randint(2, 100)
        return "0x" + ''.join(random.choice(string.hexdigits)
                              for _ in range(length * 2))

    def save_query_to_file(self, method, params):
        filename = "rpc_queries.sh"
        if self.request_id == 1:
            try:
                import os
                if os.path.exists(filename):
                    os.remove(filename)
                    logger.info(f"Deleted existing {filename}")
            except Exception as e:
                logger.error(f"Error deleting file: {e}")
        query_json = json.dumps(
            {"id": self.request_id, "jsonrpc": "2.0", "method": method, "params": params})
        wscat_command = f"wscat -c ws://127.0.0.1:9944 -x '{query_json}' | jq;" # too lazy to adapt but ofc it depends your initial params

        try:
            with open(filename, "a") as f:
                f.write(wscat_command + "\n")
        except Exception as e:
            logger.error(f"Error writing to file: {e}")

    def generate_string(self):
        length = random.randint(5, 20)
        return ''.join(
            random.choice(
                string.ascii_letters +
                string.digits) for _ in range(length))

    def generate_bool(self):
        return random.choice([True, False])

    def generate_option(self, inner_type="u32"):
        if random.choice([True, False]):
            if inner_type in self.custom_generators:
                return self.custom_generators[inner_type]()
            return self.generate_u32()
        else:
            return None

    def generate_vec(self, inner_type="u32", min_length=0, max_length=10):
        length = random.randint(min_length, max_length)
        result = []

        for _ in range(length):
            if inner_type in self.custom_generators:
                result.append(self.custom_generators[inner_type]())
            else:
                result.append(self.generate_u32())

        return result

    def parse_type_format(self, type_str):
        if type_str.startswith("Vec<") and type_str.endswith(">"):
            inner_type = type_str[4:-1]
            return self.generate_vec(inner_type)
        elif type_str.startswith("Option<") and type_str.endswith(">"):
            inner_type = type_str[7:-1]
            return self.generate_option(inner_type)
        elif type_str in self.custom_generators:
            return self.custom_generators[type_str]()
        else:
            return self.generate_hex_string()

    def generate_params_for_method(self, method):
        if method in self.method_param_patterns:
            param_types = self.method_param_patterns[method]
            params = []

            for param_type in param_types:
                params.append(self.parse_type_format(param_type))

            return params
        else:
            if "subscribe" in method:
                return []   
            elif "get" in method and "Hash" in method:
                return [random.randint(0, 10000)] 
            elif "storage" in method.lower():
                return [self.generate_storage_key()]
            else:
                return [self.generate_hex_string()]

    def call_method(self, method, params=None):
        if params is None:
            params = self.generate_params_for_method(method)

        request = {
            "id": self.request_id,
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }

        self.save_query_to_file(method, params) 


        try:
            self.socket.send(json.dumps(request))
            response_raw = self.socket.recv()
            response = json.loads(response_raw)

            if "result" in response and response["result"] is not None:
                if method not in self.success_responses:
                    self.success_responses[method] = []
                self.success_responses[method].append({
                    "params": params,
                    "result": response["result"]
                })
                logger.info(f"Success: {method} with params {params}")
            elif "error" in response:
                logger.warning(
                    f"Error: {method} with params {params}: {
                        response['error']}")

            self.request_id += 1
            return response
        except Exception as e:
            logger.error(f"Error calling {method}: {e}")
            return None

    def fuzz_method(self, method, iterations=5):
        logger.info(f"Fuzzing method: {method}")

        for i in range(iterations):
            params = self.generate_params_for_method(method)
            logger.info(
                f"Iteration {
                    i + 1}/{iterations}: {method} with params {params}")
            response = self.call_method(method, params)

            if i % 2 == 0 and response and "result" in response:
                mutated_params = self.mutate_params(params)
                logger.info(f"Mutating successful params: {mutated_params}")
                self.call_method(method, mutated_params)

            # time.sleep(0.03)

    def mutate_params(self, params):
        if not params:
            return []

        mutated = []
        for param in params:
            if isinstance(param, str) and param.startswith("0x"):
                if random.random() < 0.3:
                    mutated.append(self.generate_hex_string())
                elif random.random() < 0.5:
                    length = len(param[2:]) // 2
                    mutated.append("0x" + param[2:2 + length])
                else:
                    extra = ''.join(random.choice(string.hexdigits)
                                    for _ in range(random.randint(2, 10)))
                    mutated.append(param + extra)
            elif isinstance(param, int):
                if random.random() < 0.3:
                    mutated.append(random.choice([0, 1, 2**32 - 1, 2**64 - 1]))
                else:
                    factor = random.uniform(0.5, 1.5)
                    mutated.append(max(0, int(param * factor)))
            elif isinstance(param, list):
                if random.random() < 0.3:
                    new_length = max(0, len(param) + random.randint(-1, 1))
                    if new_length < len(param):
                        mutated.append(param[:new_length])
                    else:
                        extended = param.copy()
                        for _ in range(new_length - len(param)):
                            if param and isinstance(
                                    param[0], str) and param[0].startswith("0x"):
                                extended.append(self.generate_hex_string())
                            elif param and isinstance(param[0], int):
                                extended.append(random.randint(0, 2**32 - 1))
                            else:
                                extended.append(None)
                        mutated.append(extended)
                else:
                    # Mutate elements
                    mutated.append([self.mutate_params([item])[0]
                                   for item in param])
            else:
                mutated.append(param)

        return mutated

    def discover_param_patterns(self):
        logger.info("Discovering parameter patterns for RPC methods")

        response = self.call_method("rpc_methods")
        if response and "result" in response:
            methods_info = response["result"]
            if "methods" in methods_info:
                self.methods = methods_info["methods"]

            if "params" in methods_info:
                self.method_params_map = methods_info["params"]

        for method in self.methods:
            empty_response = self.call_method(method, [])
            if empty_response and "result" in empty_response:
                logger.info(f"Method {method} works with empty params")
                self.method_param_patterns[method] = []

            hex_response = self.call_method(
                method, [self.generate_hex_string()])
            if hex_response and "result" in hex_response:
                logger.info(f"Method {method} works with hex string")
                self.method_param_patterns[method] = ["Bytes"]

    def run_fuzzing_campaign(self, iterations_per_method=10):
        if not self.connect():
            logger.error("Failed to connect. Aborting fuzzing campaign.")
            return False

        try:
            self.discover_param_patterns()

            for method in self.methods:
                try:
                    self.fuzz_method(method, iterations=iterations_per_method)
                except Exception as e:
                    logger.error(f"Error while fuzzing method {method}: {e}")
                    continue

                # time.sleep(0.05)

            logger.info("Running targeted fuzzing on successful methods...")
            for method in self.success_responses.keys():
                logger.info(
                    f"Additional fuzzing for successful method: {method}")
                try:
                    self.fuzz_method(
                        method, iterations=iterations_per_method * 2)
                except Exception as e:
                    logger.error(
                        f"Error during targeted fuzzing of {method}: {e}")

            logger.info("Fuzzing campaign completed")

            total_methods = len(self.methods)
            successful_methods = len(self.success_responses)
            logger.info(f"Methods tested: {total_methods}")
            logger.info(
                f"Methods with successful responses: {successful_methods} ({
                    successful_methods /
                    total_methods *
                    100:.2f}%)")

            return True

        except Exception as e:
            logger.error(f"Error during fuzzing campaign: {e}")
            return False
        finally:
            self.disconnect()


if __name__ == "__main__":
    ws_url = "ws://localhost:9944"

    fuzzer = AdaptiveRPCFuzzer(ws_url)
    for _ in range(10):
        fuzzer.run_fuzzing_campaign(iterations_per_method=5)
