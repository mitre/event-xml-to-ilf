# Installation

## 

For MacOS and other systems, it is recommend to install the dependencies manually. 
There are some differences between the operating systems and how the dependencies are installed and configured, 
so there is no one right way to do this for all systems. 
This section will most likely vary for you, to some degree. 
The syslog_install.sh tries to account for this on linux, so this section will cover the installation in MacOS. 

| Package name | 
| --- | 
| redis | 
| make | 
| cmake |

* Installation of redis may require build essential or epel-release for linux systems. 

It is recommended to use a package manager for installation

```bash
brew install redis
```

with redis installed, the password must be enabled and set to the default SEAL team password. The configuration file for redis can be found in the `/etc` directory, usually located at `/etc/redis.conf`.  
Disabled by default, the option to enable is `requrepass`. Searching for `requirepass`, uncomment the line and change the password to 'Passw0rd123!'. The line should look like this.
```
requirepass Passw0rd123!
```

`brew install redis` does not initalize redis as a service unlike the linux counterparts. Therefore unless otherwise modified, the redis server will have to be started and stopped by the user. 


#### Installing redis submodules (should only be done once per system!)

hiredis:

Easiest way to install hiredis is through a package manager.
```bash
brew install hiredis
```

or 
```bash
sudo apt install -y libhiredis-dev
```

You can build redis manually but it is not reccommend. ( from the [redis++ readme](https://github.com/sewenew/redis-plus-plus#install-hiredis) - DO NOT INSTALL MULTIPLE VERSIONS OF HIREDIS.)
```
git clone https://github.com/redis/hiredis.git
cd hiredis
make
make install
```

Second, build redis-plus-plus:
```
cd lib/redis-plus-plus
mkdir build
cd build
cmake ..
make
make install
cd ../../..
```

You should see the following output:

```
Install the project...
-- Install configuration: "Release"
-- Installing: /usr/local/lib/libredis++.a
-- Installing: /usr/local/lib/libredis++.1.3.11.dylib
-- Installing: /usr/local/lib/libredis++.1.dylib
-- Installing: /usr/local/lib/libredis++.dylib
-- Installing: /usr/local/share/cmake/redis++/redis++-targets.cmake
-- Installing: /usr/local/share/cmake/redis++/redis++-targets-release.cmake
-- Installing: /usr/local/include/sw/redis++/cmd_formatter.h
-- Installing: /usr/local/include/sw/redis++/command.h
-- Installing: /usr/local/include/sw/redis++/command_args.h
-- Installing: /usr/local/include/sw/redis++/command_options.h
-- Installing: /usr/local/include/sw/redis++/connection.h
-- Installing: /usr/local/include/sw/redis++/connection_pool.h
-- Installing: /usr/local/include/sw/redis++/cxx_utils.h
-- Installing: /usr/local/include/sw/redis++/errors.h
-- Installing: /usr/local/include/sw/redis++/hiredis_features.h
-- Installing: /usr/local/include/sw/redis++/tls.h
-- Installing: /usr/local/include/sw/redis++/pipeline.h
-- Installing: /usr/local/include/sw/redis++/queued_redis.h
-- Installing: /usr/local/include/sw/redis++/queued_redis.hpp
-- Installing: /usr/local/include/sw/redis++/redis++.h
-- Installing: /usr/local/include/sw/redis++/redis.h
-- Installing: /usr/local/include/sw/redis++/redis.hpp
-- Installing: /usr/local/include/sw/redis++/redis_cluster.h
-- Installing: /usr/local/include/sw/redis++/redis_cluster.hpp
-- Installing: /usr/local/include/sw/redis++/redis_uri.h
-- Installing: /usr/local/include/sw/redis++/reply.h
-- Installing: /usr/local/include/sw/redis++/sentinel.h
-- Installing: /usr/local/include/sw/redis++/shards.h
-- Installing: /usr/local/include/sw/redis++/shards_pool.h
-- Installing: /usr/local/include/sw/redis++/subscriber.h
-- Installing: /usr/local/include/sw/redis++/transaction.h
-- Installing: /usr/local/include/sw/redis++/utils.h
-- Installing: /usr/local/include/sw/redis++/patterns/redlock.h
-- Installing: /usr/local/share/cmake/redis++/redis++-config.cmake
-- Installing: /usr/local/share/cmake/redis++/redis++-config-version.cmake
-- Installing: /usr/local/lib/pkgconfig/redis++.pc
```

You can test the redis-plus-plus install with the following command if needed: 
```
./build/test/test_redis++ -h host -p port -a auth
```