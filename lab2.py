import asyncio
import logging
from cryptography.exceptions import UnsupportedAlgorithm

from ipv8.community import *
from ipv8.lazy_community import lazy_wrapper
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8_service import IPv8

class IgnoreUnsupportedCurve(logging.Filter):
    def filter(self, record):
        # Only target this logger
        if record.name != "LabCommunity":
            return True

        if not record.exc_info:
            return True

        exc_type, exc, _ = record.exc_info

        # Suppress only this exact exception
        if (
            issubclass(exc_type, UnsupportedAlgorithm)
            # and "Curve 1.3.132.0.1 is not supported" in str(exc)
        ):
            return False

        return True


logger = logging.getLogger("LabCommunity")
logger.addFilter(IgnoreUnsupportedCurve())


COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"

# kostas = member1, clau = member2, ayush = member3
KOSTAS_KEY = "4c69624e61434c504b3a6d5bfd59dca2173b63898fdb38e4cc7cb34332695b419dca3ebc710de1b02e37bc2d2fb858a840cc8b876e33ffbfe6ae27894e928640817e08763906ada69c64"
CLAU_KEY = "4c69624e61434c504b3a4924a5ac3d83e3128007c5a349dcbda9396f45fc0331f4cd84cf5b7ec3f7b20339cafc465a0f36ddb65c4295953d01327921d7ab4ea5a7e69dcb5e16b96e0ca3"
AYUSH_KEY = "4c69624e61434c504b3a9063db4576026f2d41d5632e1be3d8f3d9acdea4e0f2676ef3bef35d4232d260a9c8cabef50ed898a2d0deb739982255f6c698996112ecef2350f945cae3d60a"


ROUND_SUBMITTERS = {
    1: KOSTAS_KEY,
    2: CLAU_KEY,
    3: AYUSH_KEY,
}

@vp_compile
class RegisterPayload(VariablePayload):
    msg_id = 1
    names = ["member1_key", "member2_key", "member3_key"]
    format_list = ["varlenH", "varlenH", "varlenH"]


@vp_compile
class RegisterResponsePayload(VariablePayload):
    msg_id = 2
    names = ["success", "group_id", "message"]
    format_list = ["?", "varlenHutf8", "varlenHutf8"]


@vp_compile
class ChallengeRequestPayload(VariablePayload):
    msg_id = 3
    names = ["group_id"]
    format_list = ["varlenHutf8"]


@vp_compile
class ChallengeResponsePayload(VariablePayload):
    msg_id = 4
    names = ["nonce", "round_number", "deadline"]
    format_list = ["varlenH", "q", "d"]


@vp_compile
class SignatureBundlePayload(VariablePayload):
    msg_id = 5
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]


@vp_compile
class RoundResultPayload(VariablePayload):
    msg_id = 6
    names = ["success", "round_number", "rounds_completed", "message"]
    format_list = ["?", "q", "q", "varlenHutf8"]


@vp_compile
class AnnounceChallengePayload(VariablePayload):
    msg_id = 100
    names = ["group_id", "nonce", "deadline", "round_number"]
    format_list = ["varlenHutf8", "varlenH", "d", "q"]


@vp_compile
class BroadcastSignaturePayload(VariablePayload):
    msg_id = 102
    names = ["nonce", "signature", "round_number"]
    format_list = ["varlenH", "varlenH", "q"]

@vp_compile
class AnnounceRoundResultPayload(VariablePayload):
    msg_id = 104
    names = ["group_id", "round_number", "success"]
    format_list = ["varlenHutf8", "q", "?"]

class LabCommunity(Community):
    community_id = COMMUNITY_ID

    def started(self):
        print("Lab community started!")
        print("Looking for peers...")

    def __init__(self, settings):
        super().__init__(settings)
        self.group_id = None
        self.signatures = {}
        self.submitted_rounds = set()
        self.rounds_completed = 0
        self.add_message_handler(RegisterResponsePayload, self.on_register_response)
        self.add_message_handler(ChallengeResponsePayload, self.on_challenge_response)
        self.add_message_handler(RoundResultPayload, self.on_round_result)
        self.add_message_handler(AnnounceChallengePayload, self.on_announce_challenge)
        self.add_message_handler(BroadcastSignaturePayload, self.on_broadcast_signature)
        self.add_message_handler(AnnounceRoundResultPayload, self.on_announce_round_result)
        
    def find_peer_by_key(self, key_hex):
        for peer in self.get_peers():
            if peer.public_key.key_to_bin().hex() == key_hex:
                return peer
        return None


    def is_ready(self):
        server = self.find_peer_by_key(SERVER_PUBLIC_KEY_HEX)
        kostas = self.find_peer_by_key(KOSTAS_KEY)
        clau = self.my_peer if self.my_peer.public_key.key_to_bin().hex() == CLAU_KEY else None
        ayush = self.find_peer_by_key(AYUSH_KEY)

        print("Ready check:")
        print("Server:", server is not None)
        print("Kostas:", kostas is not None)
        print("Clau:", clau is not None)
        print("Ayush:", ayush is not None)

        return server is not None and kostas is not None and clau is not None and ayush is not None


    @lazy_wrapper(RegisterResponsePayload)
    def on_register_response(self, peer, payload):
        peer_key = peer.public_key.key_to_bin().hex()

        if peer_key != SERVER_PUBLIC_KEY_HEX:
            print("Ignoring register response from non-server peer")
            return

        self.group_id = payload.group_id

        print("REGISTER RESPONSE:")
        print("Success:", payload.success)
        print("Group ID:", payload.group_id)
        print("Message:", payload.message)


    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge_response(self, peer, payload):
        peer_key = peer.public_key.key_to_bin().hex()

        if peer_key != SERVER_PUBLIC_KEY_HEX:
            print("Ignoring challenge response from non-server peer")
            return

        print("CHALLENGE RESPONSE:")
        print("Round:", payload.round_number)
        print("Nonce:", payload.nonce.hex())
        print("Deadline:", payload.deadline)

        for teammate in self.get_peers():
            teammate_key = teammate.public_key.key_to_bin().hex()

            if teammate_key in [KOSTAS_KEY, CLAU_KEY, AYUSH_KEY]:
                announce = AnnounceChallengePayload(
                    self.group_id,
                    payload.nonce,
                    payload.deadline,
                    payload.round_number
                )
                self.ez_send(teammate, announce)

        print("Announced challenge to teammates.")

        signature = self.sign_nonce(payload.nonce)
        key = (payload.round_number, payload.nonce)

        if key not in self.signatures:
            self.signatures[key] = {}

        self.signatures[key][self.my_key_hex()] = signature

        print("Signed server challenge. Signature:", signature.hex())

        for teammate in self.get_peers():
            teammate_key = teammate.public_key.key_to_bin().hex()

            if teammate_key in [KOSTAS_KEY, CLAU_KEY, AYUSH_KEY]:
                sig_payload = BroadcastSignaturePayload(
                    payload.nonce,
                    signature,
                    payload.round_number
                )
                self.ez_send(teammate, sig_payload)

        print("Broadcasted my signature for server challenge.")
        self.try_submit_bundle(payload.round_number, payload.nonce)


    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer, payload):
        peer_key = peer.public_key.key_to_bin().hex()

        if peer_key != SERVER_PUBLIC_KEY_HEX:
            print("Ignoring round result from non-server peer")
            return

        print("ROUND RESULT:")
        print("Success:", payload.success)
        print("Round:", payload.round_number)
        print("Rounds completed:", payload.rounds_completed)
        print("Message:", payload.message)

        for teammate in self.get_peers():
            teammate_key = teammate.public_key.key_to_bin().hex()

            if teammate_key in [KOSTAS_KEY, CLAU_KEY, AYUSH_KEY]:
                result_msg = AnnounceRoundResultPayload(
                    self.group_id,
                    payload.round_number,
                    payload.success,
                )
                self.ez_send(teammate, result_msg)

        print("Announced round result to teammates.")

        if payload.success:
            self.rounds_completed = max(self.rounds_completed, payload.rounds_completed)
            next_round = payload.round_number + 1

            if next_round <= 3:
                if self.am_submitter_for_round(next_round):
                    print("I am submitter for next round:", next_round)
                    self.request_challenge()
                else:
                    print("Waiting for submitter of round", next_round)
            else:
                print("All rounds completed.")
        
        


    @lazy_wrapper(AnnounceChallengePayload)
    def on_announce_challenge(self, peer, payload):
        peer_key = peer.public_key.key_to_bin().hex()

        print("ANNOUNCE CHALLENGE FROM TEAMMATE:")
        print("Peer:", peer_key)
        print("Group ID:", payload.group_id)
        print("Round:", payload.round_number)
        print("Nonce:", payload.nonce.hex())
        print("Deadline:", payload.deadline)

        signature = self.sign_nonce(payload.nonce)
        key = (payload.round_number, payload.nonce)

        if key not in self.signatures:
            self.signatures[key] = {}

        self.signatures[key][CLAU_KEY] = signature

        print("Signed nonce. Signature:", signature.hex())


        for teammate in self.get_peers():
            teammate_key = teammate.public_key.key_to_bin().hex()

            if teammate_key in [KOSTAS_KEY, CLAU_KEY, AYUSH_KEY]:
                sig_payload = BroadcastSignaturePayload(
                    payload.nonce,
                    signature,
                    payload.round_number
                )
                self.ez_send(teammate, sig_payload)

        print("Broadcasted my real signature.")
        self.try_submit_bundle(payload.round_number, payload.nonce)



    @lazy_wrapper(BroadcastSignaturePayload)
    def on_broadcast_signature(self, peer, payload):
        peer_key = peer.public_key.key_to_bin().hex()
        name = self.member_name(peer_key)

        key = (payload.round_number, payload.nonce)

        if key not in self.signatures:
            self.signatures[key] = {}

        self.signatures[key][peer_key] = payload.signature

        print("BROADCAST SIGNATURE FROM TEAMMATE:")
        print("Peer:", name)
        print("Round:", payload.round_number)
        print("Stored signatures:", len(self.signatures[key]), "/ 3")
        self.try_submit_bundle(payload.round_number, payload.nonce)
    

    def sign_nonce(self, nonce: bytes) -> bytes:
        return self.crypto.create_signature(self.my_peer.key, nonce)
    
    def member_name(self, peer_key: str) -> str:
        if peer_key == KOSTAS_KEY:
            return "Kostas"
        if peer_key == CLAU_KEY:
            return "Clau"
        if peer_key == AYUSH_KEY:
            return "Ayush"
        if peer_key == SERVER_PUBLIC_KEY_HEX:
            return "Server"
        return "Unknown"
    
    def my_key_hex(self):
        return self.my_peer.public_key.key_to_bin().hex()


    def find_server_peer(self):
        return self.find_peer_by_key(SERVER_PUBLIC_KEY_HEX)


    def am_submitter_for_round(self, round_number):
        return ROUND_SUBMITTERS.get(round_number) == self.my_key_hex()


    def request_challenge(self):
        if self.group_id is None:
            print("Cannot request challenge: no group_id yet")
            return

        server = self.find_server_peer()
        if server is None:
            print("Cannot request challenge: server not found")
            return

        payload = ChallengeRequestPayload(self.group_id)
        self.ez_send(server, payload)
        print("Requested challenge for group:", self.group_id)


    def try_submit_bundle(self, round_number, nonce):
        if not self.am_submitter_for_round(round_number):
            print("I am not the submitter for round", round_number)
            return

        key = (round_number, nonce)

        if round_number in self.submitted_rounds:
            return

        if key not in self.signatures:
            return

        sigs = self.signatures[key]

        if KOSTAS_KEY not in sigs or CLAU_KEY not in sigs or AYUSH_KEY not in sigs:
            print("Not enough signatures yet:", len(sigs), "/ 3")
            return

        server = self.find_server_peer()
        if server is None:
            print("Cannot submit bundle: server not found")
            return

        bundle = SignatureBundlePayload(
            self.group_id,
            round_number,
            sigs[KOSTAS_KEY],
            sigs[CLAU_KEY],
            sigs[AYUSH_KEY],
        )

        self.ez_send(server, bundle)
        self.submitted_rounds.add(round_number)
        print("Submitted signature bundle for round", round_number)

    @lazy_wrapper(AnnounceRoundResultPayload)
    def on_announce_round_result(self, peer, payload):
        self.rounds_completed = max(self.rounds_completed, payload.round_number)
        peer_key = peer.public_key.key_to_bin().hex()

        print("ROUND RESULT ANNOUNCED BY TEAMMATE:")
        print("Peer:", self.member_name(peer_key))
        print("Group ID:", payload.group_id)
        print("Round:", payload.round_number)
        print("Success:", payload.success)

        if self.group_id is None:
            self.group_id = payload.group_id
            print("Stored group_id from teammate:", self.group_id)

        if payload.success:
            if payload.round_number == 3:
                print("All rounds completed.")
                return

            next_round = payload.round_number + 1

            if next_round <= 3:
                if self.am_submitter_for_round(next_round):
                    print("I am submitter for next round:", next_round)
                    self.request_challenge()
                else:
                    print("Waiting for submitter of round", next_round)

async def main():
    builder = ConfigBuilder()

    builder.clear_keys()
    builder.clear_overlays()

    builder.add_key(
        "me",
        "curve25519",
        "lab1_key.pem"
    )

    builder.add_overlay(
        "LabCommunity",
        "me",
        [
            WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0}),
            WalkerDefinition(Strategy.EdgeWalk, 10, {"neighborhood_size": 6}),
        ],
        default_bootstrap_defs,
        {},
        []
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "LabCommunity": LabCommunity
        }
    )

    await ipv8.start()

    overlay = ipv8.get_overlay(LabCommunity)
    print("My public key:")
    print(overlay.my_peer.public_key.key_to_bin().hex())
    print("IPv8 started.")

    ready_once = False
    registered = False
    challenge_requested = False
    next_round_to_start = 1
    printed_waiting_for_start = False

    while True:
        if not ready_once:
            peers = overlay.get_peers()
            print(f"Discovered {len(peers)} peer(s)")

            for peer in peers:
                peer_key = peer.public_key.key_to_bin().hex()

                if peer_key == SERVER_PUBLIC_KEY_HEX:
                    print("FOUND THE SERVER!")
                else:
                    print("Other peer:", overlay.member_name(peer_key))


        if overlay.is_ready():
            if not ready_once:
                ready_once = True
                print("All required peers found. Stopping discovery output.")

            if not registered and overlay.rounds_completed == 0:
                server_peer = overlay.find_peer_by_key(SERVER_PUBLIC_KEY_HEX)

                payload = RegisterPayload(
                    bytes.fromhex(KOSTAS_KEY),
                    bytes.fromhex(CLAU_KEY),
                    bytes.fromhex(AYUSH_KEY),
                )

                overlay.ez_send(server_peer, payload)
                registered = True
                print("Registration sent.")

            if registered and overlay.group_id is not None and not challenge_requested and overlay.rounds_completed == 0:
                if overlay.am_submitter_for_round(next_round_to_start):
                    answer = input(f"Type START to request round {next_round_to_start} challenge, or press Enter to wait: ")

                    if answer.strip() == "START":
                        overlay.request_challenge()
                        challenge_requested = True
                else:
                    if not printed_waiting_for_start:
                        submitter_key = ROUND_SUBMITTERS[next_round_to_start]
                        submitter_name = overlay.member_name(submitter_key)

                        print(f"Waiting for {submitter_name} to start round {next_round_to_start}...")
                        printed_waiting_for_start = True

        else:
            print("Waiting for server and teammates...")

        await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())