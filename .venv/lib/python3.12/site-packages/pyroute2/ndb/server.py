import logging
logging.basicConfig(level=logging.DEBUG)
from pyroute2.iproute.linux import IPRoute, NetNS
import asyncio
from pyroute2.ndb.schema import DBSchema, DBProvider

async def consume(sock, event_map):
    while True:
        async for msg in sock.async_get():
            for handler in event_map.get(msg.__class__, [lambda x, y: None]):
                try:
                    target = msg['header']['target']
                    handler(target, msg)
                except Exception as e:
                    print(" EEEE ", e)
                finally:
                    print(" >>>> ", msg)


async def main():

    ipr = IPRoute()
    ns = IPRoute(netns='test')
    event_map = {}

    db = DBSchema(
        {
            'rtnl_debug': True,
            'provider': 'DBProvider.sqlite3',
            'spec': ':memory'},
        [ipr, ns],
        event_map,
        logging.getLogger()
    )

    print(db.event_map)
    ipr.bind()
    ns.bind()

    loop = asyncio.get_running_loop()
    loop.create_task(consume(ipr, db.event_map))
    loop.create_task(consume(ns, db.event_map))

    while True:
        db.export() 
        await asyncio.sleep(10)


asyncio.run(main())
