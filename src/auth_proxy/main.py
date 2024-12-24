import asyncio
import argparse
from yaml import safe_load


from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from .dispatch import AuthDispatch
from .data_models import AuthProxyConfig


def main():
    parser = argparse.ArgumentParser(
        prog='Auth Proxy',
        description='Proxy for handlig authentication of HTTP services.',
    )
    parser.add_argument('config_file', type=str, help='configuration file')
    args = parser.parse_args()

    asyncio.run(run(args.config_file))


async def run(config_file: str):
    with open(config_file, 'r') as file:
        config = AuthProxyConfig.model_validate(safe_load(file))

    opts = options.Options(**config.proxy)
    m = DumpMaster(opts)
    m.addons.add(AuthDispatch(config.auth))
    await m.run()
