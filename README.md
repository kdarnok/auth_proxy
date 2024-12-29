# Authentication proxy
HTTP proxy server for transparently authenticating access to admin frontends of devices residing
in my home network.

## Motivation
There are quite a few devices (e.g. router, switch, pv battery)
in my home network that offer some more or less secure admin frontends.
After making sure any plain text authentication requests cannot be intercepted by other devices
in the home network, another nuisance remains: each of them requires a separate password,
some of their login pages are not recognised by browsers or password managers, and they usually
come with session timeouts.

This proxy's task is to keep these admin frontend sessions alive: intercepted traffic
(using the [mitmproxy](https://mitmproxy.org/) package) is analysed
to identify expired sessions (s.a. redirects to login pages, or HTTP error codes), new sessions
are created by logging in again and the response from the new session returned to the user.

## Operation

### Automatic proxy configuration
To make this proxy only intercept the traffic to those select services, a `proxy.pac` file is
used. This is a slim javascript file that is used by the browser to figure out if a proxy (and which one)
should be used for a given URL:

```
function FindProxyForURL(url, host) {
    if (host.endsWith(".skynet") || host == "skynet") {
        return "PROXY localhost:1234";
    } else {
        return "DIRECT";
    }
}
```

This causes all traffic to the `.skynet` TLD to be sent through the proxy residing at `localhost:1234`
(that TLD does not need to be resolvable through DNS, as it is only used inside that proxy).
After creating that file, let the browser know about this (e.g. "Automatic proxy configuration URL" in Firefox
connection settings) using a `file://` uri.

### Proxy configuration
Next, create a YAML file containing a section about the proxy server

```
proxy:
    listen_host: 127.0.0.1
    listen_port: 1234
```

as well as one for setting the TLD and an arbitrary number of host entries:

```
auth:
    tld: skynet

    hosts:
        sonnenbatterie:
            handler:
                cls: auth_proxy.Sonnen
                config:
                    password: <password>
            description: Sonnenbatterie

        fritzbox:
            handler:
                cls: auth_proxy.FritzBox
                config:
                    username: <fritzbox user name>
                    password: <password>
            description: FRITZ!Box

        gs1900:
            handler:
                cls: auth_proxy.ZyxelGS1900
                config:
                    password: <password>
            description: Zyxel GS1900 switch
```

For each host to be covered by the proxy, a handler (by means of a dotted python path to
an `AuthHandler` class) needs to be specified, as well as all the config data this class
needs.

The keys in the `auth.hosts` section are the second level domain names below the proxy TLD, as well as the hostnames
by which they are usually accessible.

### Running the proxy

Once this is all set up, install the python package (clone the repository and run `pip install -e.` inside it).
Then, run `auth-proxy <your_config_yaml>` and point your browser to the `tld` set in the config file (here: `skynet`),
which will offer you a link for each of the configured hosts.
