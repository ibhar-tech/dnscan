import asyncio
import aiodns

async def main():
    resolver = aiodns.DNSResolver()
    try:
        res = await resolver.query('google.com', 'A')
        print("A:", [r.host for r in res])
    except Exception as e:
        print("A error:", e)
        
    try:
        res = await resolver.query('google.com', 'NS')
        print("NS:", [r.host for r in res])
    except Exception as e:
        print("NS error:", e)
        
asyncio.run(main())
