from atproto import Client

identifier = "postac001.bsky.social"          # xxxx.bsky.social
password = "zmsm-26ou-e5m7-uig5"  # 19文字

client = Client(base_url="https://bsky.social")
client.login(identifier, password)

print("LOGIN SUCCESS")
