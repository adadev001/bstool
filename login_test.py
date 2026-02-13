from atproto import Client

identifier = "ID"          # xxxx.bsky.social
password = "PASS"  # 19文字

client = Client(base_url="https://bsky.social")
client.login(identifier, password)

print("LOGIN SUCCESS")
