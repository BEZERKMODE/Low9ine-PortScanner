import asyncio

SEM = asyncio.Semaphore(100)

async def scan_port(host, port):
    async with SEM:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=0.5
            )
            writer.close()
            await writer.wait_closed()
            return port, "open"
        except asyncio.TimeoutError:
            return port, "filtered"
        except:
            return port, "closed"

async def scan_ports(host, ports):
    tasks = [asyncio.create_task(scan_port(host, p)) for p in ports]
    return await asyncio.gather(*tasks)