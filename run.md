**Central Server**
```cd ./central_server
uvicorn central_server:app --reload```

**VPN Server**
```sudo python3 -m tests.test_server```

**VPN Client**
```sudo python3 -m tests.test_client```

**Test VPN**
```ping -I tun1 google.com```