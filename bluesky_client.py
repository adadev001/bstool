import os
from atproto import Client

class BlueskyClient:
    def __init__(self, dry_run=True):
        self.dry_run = dry_run
        self.client = None

        if not dry_run:
            self.client = Client()
            self.client.login(
                os.environ["BLUESKY_IDENTIFIER"],
                os.environ["BLUESKY_PASSWORD"]
            )

    def post(self, text):
        if self.dry_run:
            print("---- DRY RUN POST ----")
            print(text)
            print("----------------------")
        else:
            self.client.send_post(text)
