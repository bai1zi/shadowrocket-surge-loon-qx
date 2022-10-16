#!name=腾讯视频
#!desc=去除腾讯视频广告
#需先卸载重装，只保留开屏部分其他全部注释掉，打开app登录账号后关掉，在恢复注释就行，开屏部分需要你自己建立个txt文件随便写个文字后缀在改成mp4，在[Map Local]里选择文件返回，千万不要直接拦截。

[Rule]
AND,((PROTOCOL,HTTPS), (DOMAIN,iacc.qq.com)),REJECT-NO-DROP

# > 开屏
[Map Local]
^http:\/\/(.+\.tc\.qq\.com\/.+mp4|pgdt\.gtimg\.cn) data="1 4.mp4" //自己设置


[Script]
腾讯 = type=http-request,pattern=^(https:\/\/i\.video|http:\/\/iacc)\.qq\.com\/$,requires-body=0,max-size=0,script-path=


[MITM]
hostname = %APPEND% i.video.qq.com,iacc.qq.com


#****
let size = ($request.headers["content-length"] || $request.headers["Content-Length"]  );
if(size < 1500){$done();}
$done({});
