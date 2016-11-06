Tỉnh dậy sau cơn mây mưa với đồng đội đêm qua, ghé thăm lại những gì bỏ sót:  
`Thank you for hacking with us. We have 3 prizes for 3 awesome writeups. Drop us a line @link`  
Mình cảm thấy cần phải làm gì đó, đơn giản vì mình thần tượng mấy anh [VNSec](http://www.vnsecurity.net/), cùng vô số người nữa  
## `ze` - RE 50 pts
10 đội giải được, 20 đội giải được, thời gian trôi càng nhanh...  
4 tiếng trôi qua, và nhận ra mình đi xa quá. Trong khi anh Worm thì cứ đi qua dụ mình mua flag, mình nhất quyết nói không. Như vậy là không công bằng  
```c
if strtoul(input, 0, 17) == 53:
	print("SVATTT{%s}",input)
```
Convert từ base-10 → base-17: 53 → 32   
Nhập '00000032', boooombb  
4 tiếng để giải quyết bài toán này, mình vẫn cảm thấy đó là 1 sự xúc phạm, mình cũng không hiểu vì sao lại như thế

## `mrc` - RE 150 pts
Thuật toán, mật mã là điều gì đó khá xa xỉ với mình, mình thích hardcore và sự thô thiển  
[mrc.c](https://gist.github.com/khtq/c82f7879c228295cdea2d1bc21aaf58b)

## `admincp` - Web 200 pts
Gần cuối giờ thi đấu, đội mình vẫn đang top 10, anh em vẫn đang hừng hực khí thế, ngay cả khi cả đội quyết định không ăn trưa, thật là tội đồ nếu như mình vẫn đâm đầu vào bài RE 200pts mà không ra. Và mình quyết định chuyển sang làm bài khác khi đồng đội nói rằng đéo phải web đâu, là crypto, mình k tin nó.   
Thật không văn minh nếu như giải bài này khi đã có source

    Traceback (most recent call last):
      File "/home/admincp/server.py", line 30, in <module>
        cipher = buffer.split('GET /login/')[1]
    IndexError: list index out of range

Let's input:  
`http://128.199.128.238:31333/login/aaaaaaaaaaaaaaa`
    
Response:    

	Your credential: sdfsdfsdfsd
	Traceback (most recent call last):
	  File "/home/admincp/server.py", line 43, in login = json.loads(AES.new(KEY, AES.MODE_OFB, IV).decrypt(cipher.decode('hex')))
	  File "/usr/lib/python2.7/encodings/hex_codec.py", line 42, in hex_decode output = binascii.a2b_hex(input)
	TypeError: Odd-length string    

Tiếp tục:  
`http://128.199.128.238:31333/login/12345678901234561234567890123456`

	Your credential: 12345678901234561234567890123456
	Traceback (most recent call last):
   	  File "/home/admincp/server.py", line 43, in login = json.loads(AES.new(KEY, AES.MODE_OFB, IV).decrypt(cipher.decode('hex')))
	  File "/usr/lib/python2.7/json/__init__.py", line 339, in loads return _default_decoder.decode(s)
	  File "/usr/lib/python2.7/json/decoder.py", line 364, in decode obj, end = self.raw_decode(s, idx=_w(s, 0).end())
	  File "/usr/lib/python2.7/json/decoder.py", line 382, in raw_decode raise ValueError("No JSON object could be decoded")
	ValueError: No JSON object could be decoded
	
Như vậy, chúng ta sẽ phải tìm một ciphertext sao cho input có thể parse vào `json.loads()`  
[OFB Mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_Feedback_.28OFB.29)  
![ofb mode decryption](https://upload.wikimedia.org/wikipedia/commons/f/f5/OFB_decryption.svg)    
Các exception thật không tự nhiên, mình nghĩ vậy, nếu không thì thật là vô lý  
file decoder:  
`$PYTHON_PATH/Lib/json/decoder.py`

Mình sẽ test vài ký tự để kiểm tra Exception:
```python
>>> import json
>>> json.loads('{aaaaaaaaaaaaaaa')

Traceback (most recent call last):
  File "<pyshell#4>", line 1, in <module>
	json.loads('{aaaaaaaaaaaaaaa')
  File "C:\Python27\lib\json\__init__.py", line 339, in loads
	return _default_decoder.decode(s)
  File "C:\Python27\lib\json\decoder.py", line 364, in decode
	obj, end = self.raw_decode(s, idx=_w(s, 0).end())
  File "C:\Python27\lib\json\decoder.py", line 380, in raw_decode
	obj, end = self.scan_once(s, idx)
ValueError: Expecting property name: line 1 column 2 (char 1)

>>> json.loads(' {aaaaaaaaaaaaaaa')

Traceback (most recent call last):
  File "<pyshell#5>", line 1, in <module>
	json.loads(' {aaaaaaaaaaaaaaa')
  File "C:\Python27\lib\json\__init__.py", line 339, in loads
	return _default_decoder.decode(s)
  File "C:\Python27\lib\json\decoder.py", line 364, in decode
	obj, end = self.raw_decode(s, idx=_w(s, 0).end())
  File "C:\Python27\lib\json\decoder.py", line 380, in raw_decode
	obj, end = self.scan_once(s, idx)
ValueError: Expecting property name: line 1 column 3 (char 2)
```
Ý tưởng của mình là sẽ dùng `{` kết hợp space `' '` để brute force output của IV dựa vào exception trả về (gần giống như [POA](https://en.wikipedia.org/wiki/Padding_oracle_attack) vậy), sau đó sẽ control được plaintext (`plaintext[i] = output[i] ^ ciphertext[i]`) thành một chuỗi JSON  

[admincp.py](https://gist.github.com/khtq/d5df3ae31426d4107c9efaf34c75859f)
    
	C:\Users\k\Desktop>python admincp.py
	Finding ouput[0]
	Found satisfy input: 0x98       =>      output: 0xe3
	Finding ouput[1]
	Found satisfy input: 0xba       =>      output: 0xc1
	Finding ouput[2]
	Found satisfy input: 0x8d       =>      output: 0xf6
	Finding ouput[3]
	Found satisfy input: 0xa9       =>      output: 0xd2
	Finding ouput[4]
	Found satisfy input: 0x39       =>      output: 0x42
	Finding ouput[5]
	Found satisfy input: 0x9d       =>      output: 0xe6
	Finding ouput[6]
	Found satisfy input: 0x1d       =>      output: 0x66
	Finding ouput[7]
	Found satisfy input: 0x6a       =>      output: 0x11
	Finding ouput[8]
	Found satisfy input: 0x8c       =>      output: 0xf7
	Finding ouput[9]
	Found satisfy input: 0x72       =>      output: 0x9
	Finding ouput[10]
	Found satisfy input: 0x92       =>      output: 0xe9
	Finding ouput[11]
	Found satisfy input: 0x8        =>      output: 0x73
	Finding ouput[12]
	Found satisfy input: 0x7f       =>      output: 0x4
	Finding ouput[13]
	Found satisfy input: 0xd7       =>      output: 0xac
	Finding ouput[14]
	Found satisfy input: 0xcc       =>      output: 0xb7
	Finding ouput[15]
	Last byte.....
	Found satisfy input: 0x8f       =>      output: 0xf4
	Done
	Output: e3c1f6d242e66611f709e97304acb7f4

	Your credential: 98e397f078c40473956b8b1166ce9589
	Traceback (most recent call last):
	  File "/home/admincp/server.py", line 47, in <module>
		if login['user'] == 'admin':
	KeyError: 'user'    
	
Yay
```python
>>> import requests
>>> 
>>> output = "e3c1f6d242e66611f709e97304acb7f4".decode("hex")
>>> wanted = '{"user":"admin"}'
>>> print requests.get("http://128.199.128.238:31333/login/" + "".join([chr(ord(x) ^ ord(y)) for x,y in zip(output, wanted)]).encode("hex")).content

Your credential: 98e383a12794442bd5688d1e6dc29589
Here is your reward: SVATTT{sorry_this_aint_totally_cryptography_using_crypto_w1sely_btw}
```  
Cá nhân mình thấy bài này không khó, thế nhưng vẫn không có đội nào chịu submit  
Kết thúc cuộc thi team mình đứng ở vị trí thứ 2, cảm ơn tất cả các nhà tài trợ cùng BTC, và cảm giác teamwork cùng đồng đội thật tuyệt. Mặc dù mình biết kết quả đạt được còn một phần may mắn. I know it man. Tuy nhiên, đó vẫn là một khoảnh khắc thực sự tuyệt vời. Cũng cảm ơn chủ nhà MTA, rất chu đáo  
Btw, bạn thấy giọng văn của mình giống ai đó? Bạn đúng mẹ nó rồi đó, mình thần tượng nhiều lắm mà, again =))
