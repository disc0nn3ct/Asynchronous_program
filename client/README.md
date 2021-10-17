Чтобы собрать и запустить: 
```shell
mkdir build && cd build && cmake .. && make && ./socks5_client
```

Будет ~ такой вывод: 

```
HTTP/1.1 200 OK
access-control-allow-origin: *
content-type: text/html; charset=utf-8
content-length: 15
date: Tue, 12 Oct 2021 22:14:41 GMT
x-envoy-upstream-service-time: 1
Via: 1.1 google

109.252.115.147
```

Для замеров был сформирован [скрипт](script.sh)

```shell
chmod +x script.sh
./script.sh

```

После выполнения будет сформирован log.txt файл с результатами замеров. 