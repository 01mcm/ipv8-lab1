import asyncio
import logging

logging.getLogger("LabCommunity").setLevel(logging.CRITICAL)

from ipv8.community import *
from ipv8.lazy_community import lazy_wrapper
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8_service import IPv8


COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"

@vp_compile
class SubmissionPayload(VariablePayload):
    msg_id = 1
    names = ["email", "github_url", "nonce"]
    format_list = ["varlenHutf8", "varlenHutf8", "q"]


@vp_compile
class ResponsePayload(VariablePayload):
    msg_id = 2
    names = ["success", "message"]
    format_list = ["?", "varlenHutf8"]
    

class LabCommunity(Community):
    community_id = COMMUNITY_ID

    def started(self):
        print("Lab community started!")
        print("Looking for peers...")

    def __init__(self, settings):
        super().__init__(settings)
        self.add_message_handler(ResponsePayload, self.on_response)

    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer, payload):
        peer_key = peer.public_key.key_to_bin().hex()

        if peer_key != SERVER_PUBLIC_KEY_HEX:
            print("Ignoring response from non-server peer")
            return

        print("SERVER RESPONSE:")
        print("Success:", payload.success)
        print("Message:", payload.message)


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
            WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0}),
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
    print("IPv8 started.")

    EMAIL = "m.c.montalvo@student.tudelft.nl"
    GITHUB_URL = "https://github.com/01mcm/ipv8-lab1.git"
    NONCE = 255392953

    submitted = False

    while True:
        peers = overlay.get_peers()
        print(f"Discovered {len(peers)} peer(s)")

        for peer in peers:
            peer_key = peer.public_key.key_to_bin().hex()

            if peer_key == SERVER_PUBLIC_KEY_HEX:
                print("FOUND THE SERVER!")

                if not submitted:
                    print("=== SENDING TO SERVER ===")
                    print("Email:", EMAIL)
                    print("GitHub URL:", GITHUB_URL)
                    print("Nonce:", NONCE)

                    payload = SubmissionPayload(EMAIL, GITHUB_URL, NONCE)
                    overlay.ez_send(peer, payload)

                    submitted = True
                    print("Submission sent.")

            else:
                print("Other peer:", peer_key)

        await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())