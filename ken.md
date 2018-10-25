> 本文翻译自：https://www.crowdstrike.com/blog/your-jenkins-belongs-to-us-now-abusing-continuous-integration-systems/
>- 名词解释：
>- Post-Exploitation: 攻陷目标中的某一台或者多台主机之后做的一些事情，包括但不限于：识别已经拿下主机的价值以及维持访问。主机对于攻击者来说是否具有一定的价值、具有多大的价值主要从以下两个个方面考虑：是否有敏感信息、数据，是否能够在后期的渗透中发挥价值。比如被攻陷的主机是否是组织中的关键人物、高层领导、系统管理员，被攻陷的主机是够能够尽可能的有内网不同网段的访问权限等等。
>- Active Directory：Active Directory中文翻译为活动目录，这个概念不需要太过深入纠结，简单的理解它：Active Directory（活动目录）是微软Windows Server中，负责架构中大型网路环境的集中式目录管理服务（Directory Services），Windows 2000 Server开始内建于Windows Server产品中，它处理了在组织中的网路物件，物件可以是计算机，用户，群组，组织单元（OU）等等，只要是在Active Directory结构定义档（schema）中定义的物件，就可以储存在Active Directory资料档中，并利用Active Directory Service Interface来存取。
>- Groovy：Groovy是一种运行在JVM上的动态语言,它吸取了Python,Ruby和Smalltalk等语言的优点
>- Freestyle Project： Jenkins可用于执行典型的构建服务器工作，例如执行连续/官方/夜间构建，运行测试或执行一些重复的批处理任务。这被Jenkins被称为"Freestyle Project"

## 滥用持续集成系统Jenkins

![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/1.jpg)

### 介绍
Jenkins是业界领先的开源自动化服务平台，在开发团队中很受欢迎。最近，我们观察到攻击者瞄准了大规模的[Jenkins服务器](https://jenkins.io/)，以部署[密码器](https://www.crowdstrike.com/blog/cryptomining-harmless-nuisance-disruptive-threat/。他们还发起了针对Jenkins目标的违规行为，以保持拥有开发者环境的访问权限。有几篇很好的博客文章讨论了通过漏洞，Web控制台和后期利用(Post-Exploitation)来获取Jenkins的权限。

本博文侧重于阐述攻击者获得访问、维护和渗透数据的常用技术。在开发环境受到损害的情况下，CrowdStrike的红客团队利用这些技术进行对抗模拟演练。

### 针对Jenkins
根据使用情况的不同，定位和识别出Jenkins服务器也会有所不同。对于很多红客团队来说，在内部网络的某个地方可以访问Jenkins，对这些服务器的访问权限也可以通过多种方式获得。最常见的方法是使用最近公开的漏洞和利用它们、认证插件中的错误配置以及先前获得的凭据。

漏洞利用并不总是用于有针对性的破坏。然而，近期观察到Jenkins漏洞被多次利用。

### Java反序列化
Java反序列化漏洞(CVE-2017-1000353)可以用于在未打补丁的Jenkins服务器上远程执行代码。Exploit-db（https://www.exploit-db.com/exploits/41965/）包含一个可以用来测试这个问题的可修改的POC。

在没有使用漏洞利用的情况下，对手通常会利用先前泄露的凭据或配置错误的Jenkins服务器来获取访问权限。默认情况下，Jenkins需要身份验证，但这点通常会被开发团队所更改，并且可能会使服务器更加容易受到攻击，这具体要取决于配置方式。Jenkins支持各种身份验证插件，包括LDAP，Kerberos单点登录（SSO），SAML等。最常见的错误配置之一是在下面所示的全局安全配置中的匿名读访问授权，如下所示。

![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/2.jpg)


虽然默认不启用，但可以利用匿名读取访问来访问构建历史记录和凭据插件。在某些情况下，还启用了匿名脚本对控制台访问，这将完全访问到Java运行时的情况，从而允许命令执行。因此强烈建议锁定对Jenkins的访问，尤其是Web控制台，因为错误配置的身份验证插件是攻击者获取Jenkins访问权限并进一步完成任务的常见方式。

身份验证插件允许开发团队自定义登录到他们的环境。这些插件因组织而异，例如，没有Active Directory的组织可能会选择使用[Google的登录插件](https://wiki.jenkins.io/display/JENKINS/Google+Login+Plugin)。需要注意的是，不管以什么方式实现，这些认证方法都应该得到适当的保护。目前已经有攻击者利用身份验证方法来获取Web控制台访问权限的实例，因此，这些方法应该在边界用例中进行彻底的测试。例如，如果使用[Active Directory插件](https://wiki.jenkins.io/display/JENKINS/Active+Directory+plugin)，那是否所有活动目录用户都允许对Web控制台进行身份验证？如果是这样，已获得域凭据的攻击者将能够验证并尝试利用Jenkins服务器。

### Jenkins的后期利用
Jenkins是一个支持各种操作系统的Java应用程序，最常见的操作系统有Windows，Ubuntu/Debian和RedHat/CentOS。虽然Jenkins Web应用程序的功能基本上是相同的，但Windows和Linux安装之间还是存在一些显著的差异，如下所述：

#### Windows操作系统
默认情况下，当安装在Windows上时，Jenkins将使用NT AUTHORITY\SYSTEM帐户。强烈建议更改此用户帐户，因为SYSTEM权限帐户对Windows系统具有完全访问权限。如果要访问脚本控制台，攻击者可以相对更轻易地完全控制系统。一般情况下，建议使用具有有限权限的本地系统的服务帐号。

#### Linux操作系统
默认情况下，当安装在Linux上时，Jenkins会创建一个服务帐号。默认情况下，此用户帐户没有sudo或root访问权限，但是，检查一下还是很有必要的。如果要访问脚本控制台，则攻击者将拥有与Jenkins服务帐户相同的权限。

#### 脚本控制台
[Jenkins脚本控制台](https://wiki.jenkins.io/display/JENKINS/Jenkins+Script+Console)是一个在Web控制台允许用户执行Jenkins Groovy脚本的可视应用程序。当访问它的时候，脚本控制台允许完全访问Java，并且可以利用它在Java运行时的进程中执行任何操作。最值得留意的是执行命令的能力，如下所示，适用于Linux和Windows安装。
![](https://ginove.obs.cn-north-1.myhwclouds.com:443/jenkins/3.png?AccessKeyId=DXQ3PVZI6LS86XIGLVN5&Expires=1540467936&Signature=%2Bv1cu0tlDwFa6FLBbefIqkC%2F19o%3D&x-obs-security-token=gQpjbi1ub3J0aC0xioLi_4LJbPWlfpplGezqdfbq8dkWNLZZAu6FSO3SzmXdHAsgdrmBkyEKzPZVrd-bV7vkWqOB9-3c_lzEf0ap9iMic9YV_1gK7f4qqHJU8chqrZ_YWECwqBlg_00uyngvJCXEtEsP6sgWEVBgijv2aI15S52viVYE44cE7POflx-fQ0rgItdgnQuHKb08ZaPXVEr6WA9hXtNTW4_nT50pnnJ8Ficgy-YQsUBd2K6S1pS9wPnnxiSkCT6dmObKNMslElsOfAZXslx4wRiqzgWoQlbKyVc4fBGi23fiSlQQKLlqniqQzuZ5pU54NcO7QmsqHANxsI1IPXVh3PU3cpYZr7IZd0F1juiYbO_D6JMNv0cOy9BS1SunCfmS4N7iueu1g8KbUl6Yet-L-Bt8gH5rLRWVvxVC4EG6m9GbOtVf-ywgj-qiM_TWR6fFJaXC4xcnzFkh6GBp0Iw1PWd0uAgLS654zPXKq98Z_LaUaQL7oWpOez5sPFqoAwqvePsGJJfhs0Qhk5EuMP70PlWobKp9fkTuBhHOXBslZrix9Di-rqONVWEDPCAzs4P_9InQYmz4S01I2btVN748TIGztGvSFjjs5W4dFRUvsMZzo5Pqb7fg-70RsBsl9TYMnFa5tyr8mG8czi1rSk8ikEe2u8320Vb2l-YSEv_OCbWQUuFWRI6nFDzjPAuAl2FyyFlo1vD8t1hSaOnkrquDm3pk--ZSgdc%3D)

![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/4.jpg)

在这儿，攻击者可以生成信标，列表文件，解密存储的密码等。请注意，使用[execute](http://docs.groovy-lang.org/latest/html/groovy-jdk/java/lang/String.html#execute(java.lang.String[],%20java.io.File)方法，所有命令都将作为Java进程的子进程（Windows上的Java.exe和Ubuntu上的/usr/bin/java）运行。

在检测恶意Jenkins服务器活动时，检测恶意可疑的进程树是一个有用的指标。例如，通过脚本控制台生成PowerShell命令时，会发现以下情况：

![](https://ginove.obs.cn-north-1.myhwclouds.com:443/jenkins/5.png?AccessKeyId=UM65QQ8FUTUXIBTZB36M&Expires=1540468022&Signature=BmIzDqvBFEepeFXcIYWNLdqvaC8%3D&x-obs-security-token=gQpjbi1ub3J0aC0xigJFeS25YbWXOpPRQlN0xXIiasGpRdpTIJIao8ozZi2P95RekiZrvjxwQCiN74aJZae1CQ3f0wVq0VH3WaxUh2-2SetH64RYGdxBw44u8WtJBJki9Fly92J0FSeTa7HXxMrGsdDB4R1eZTvPE4x-NgkkVSAM6iFL0BWnVokG3STmeBC3U-4Hw8GBKBRtTXk3U1WOpKh-Ae-_0F0YoaX40H_u9mJQkDSCvwrpuF7OrAre0QEsPxwPGGprZGBMIXC1faXulBQot8TnEogw1MW2P0JRrTMf9TBrk21Vv2sX4TLgFsIbC5mH9tuXw1K8L2vnloqRdlKiMtgI4wdSA0PpGJBYNnayTQ5h1vzUq6p-t4Pl5SOVT3gundQIomDriqr3X7k5YmiX_zbetzBJYUOmAvc6LNJ2JTZlEqMaQZV8mDtZlDkF9jYnj5NgqBxZCmjgYD1-3Oxvy8tDP41GFp_L3dEGgulipna7HEmd4qwNncPWV5XO4wqyIIFsuKHdqzd1UObApN46kU5Vf64Svz_Ji4d1U0bpsT1xgPDOMGc19J-9Z3nTg2cgl8yCY5goY8YILBdgtxoxerinLLEINkcXIyE8s2PM2Tv83Gy8JTRC4DBDwQXoef876ZtNFTR6B_Yc-9DRK-T-JonKz7t7yx-A9cvUn9FR25ZOmwcZl-bAdehjc0dx3_DJixmNDYeRgqWV1x_VpK0JjosaEWP7pGswyH4%3D)


在某些情况下，攻击者可能会选择通过使用内置的Java方法来避免产生命令和控制的方法，而不是依靠PowerShell来执行后期利用。在许多Jenkins妥协方案中，攻击者将会试着访问这些文件：`credentials.xml`，`master.key`和`hudson.util.Secret`。这些文件负责加密重要秘密信息的，在某些情况下，还负责存储凭据。`master.key`文件用于加密`hudson.util.Secret`文件，`hudson.util.Secret`文件用于加密凭证插件中的秘密信息。`credentials.xml`文件则包含Jenkins用户的加密密码和密钥。

获得这些文件的方法有很多种。如果为服务器建立了SSH访问或命令和控制方法，则可以直接从服务器复制这些文件并将其解压缩。在此示例中，攻击者利用内置的Java方法通过利用以下Groovy脚本来获取这些文件：

![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/6.jpg)

使用上面的Groovy脚本，攻击者能够检索每个文件而不会产生潜在的恶意子进程。攻击者还使用 [Base64类方法](http://docs.groovy-lang.org/2.4.3/html/api/org/codehaus/groovy/runtime/EncodingGroovyMethods.html)来检索二进制格式的`hudson.util.Secret`文件。我门可以使用Jenkins测试实例来查看这个脚本的用法。

![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/7.jpg)

存储在`credentials.xml`文件中的密码短语也可以使用以下脚本从脚本控制台中直接解密：
![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/8.jpg)

![](https://ginove.obs.cn-north-1.myhwclouds.com:443/jenkins/9.png?AccessKeyId=050DH0KPWA3TSYZPKRPZ&Expires=1540468038&Signature=d9v3SQA8oZLf7RcxANniT%2FvAMDw%3D&x-obs-security-token=gQpjbi1ub3J0aC0xiggtMIu-XwXox8AUZUZYHNijSAfslqyzegCO7SPIzD6qCBQsOxb3NP8wvqk6hD-KcOna8XTHXyq2NzVfgv7Vl9M3cU89ICfiFoj2ygxBR-sanNDK9z6x8sK70qxmxb48QjjWHh2FHS0JxcBjUbUGCe4wxOFTO_ipxrZOlXu9YebucljYL2eD21C1MLNttT2ywD5IPu5vPX_hR-VrhBcHVPMkgALofMCn-Uf0MM_UI8p-AoLnVc5ahySM3TfHdLhgC22kIamDqbp6RlLnLCZbT1uaY1ljQaYYomOIWGNmU4jbMnPoGf1XcuID_tvDithta7ZptaUK7eKWIloYQjhUDVboQW3v2O2SqEKKPdZwoOJUnej9dbZbSGAADtx7V4joq19L6usQ1j9GDmsn1UhTS69A2f7dPTp_aKFUSsNff0RLnC2nSEmuMvV4lBuZx3zIox_fwt3AEy62puzarUsHfZAko0hUBuDvONnLiyQIHil8I6YRt7l9HK1ksY1Jrlmm9kPF830jO8dH-nd6jQKwtYqwsKfZEeueL62TCzxceDyByP1cwaOow099fZuoFfEoxm8BGp_VWU6YYDHOSMKRka_raDIjjr0tz95D23zInffmfhTrnQCoTTs-NHSgZ71A2vDWtghJB4eOsW83xRcTcKs76qu92VVcj3W9WMkvYwFzUgGyTTnjQt0U7Ja9YUfCTjX4l5rQJMWoB_mNBEkMICU%3D)

访问Jenkins脚本控制台为攻击者提供了各种方法来获取Jenkins服务器上关键且敏感的文件，因此应禁用或禁止访问。

### Job配置/创建
在无法访问脚本控制台的情况下，可以查看Web控制台和潜在调度作业或查看构建历史的用户仍然可以根据配置获取有价值的信息。在几项评估中，CrowdStrike红客团队确定了可以重新配置Job但未被创建的情况，反之亦然。

通过查看默认页面，可以通过Web控制台确定经过身份验证的用户的权限，如示例所示。在该方案中，用户无需进行身份验证即可配置/创建Job。

![](https://ginove.obs.cn-north-1.myhwclouds.com:443/jenkins/10.png?AccessKeyId=GCACQ61SC7CLOWIK6L3K&Expires=1540468053&Signature=x%2FXOvEvYYfPMSa6S5vC2JK8sEOA%3D&x-obs-security-token=gQpjbi1ub3J0aC0xiok-1s5RIkWKiYWqBT-zEHjBUrjruk7z-O_XgZU-pCvvzM6TzuZmmF2V7driaTpbEUj8hIIUvq4j59IE81hj1z3eZPp34SjWzUPMk9U6jC-zWonsIfmE7lP__M9MJCZQng9bXCslJGDBu4bBT2HP3Q_0FoiwQjhaBpxnPJH5f_khPRcv1OW4J5na1sekk9jsS9FmtjxAisg_rJ-086SkvdsfdXRM4hKqlaF2i1n3ucA0LRyPV8Kc6PIspPnlfLTW9LpI2NJzKH8HzpXlYTwguXvjSg5WsXkRKTR0-EmwUsVpsTslMlTZIrUpprKU6gMpCfjXLy_4stxGYBhKJ65PkV2eGqnLmW0JbY77j0T5GCHPfHrCFlc8VOdJzA8skzWKx7vpYiCgm_Xyl71mCE-zPORjykozUJXxRETejAGULcU0cv-pIjymhvlZ0ZET8QBBwv90YHOhPdDju4bLNeQEjGTFtx-Pi9oxKeNlg7_wiUPZkRGA_xrfye5p6P31LMYs6upwWD3HBSs3p4MxSRPGS2YO_RqfOXUVMmTpaHyoLauo6JzMAp5RNzjfYaYrtsvWl2QMLxq29u-ytWIDZUX4N-RCD6wxU3jP6_4GzwvyxDWdgJ0sxKjAu9WaA6ioU33Um4tki4D5eiDkY5wryWzGjOrFj1IURdCCAxEojl4nPpwBsFyukCTK-xJbG1mCHFwh9T2DbTSVrQevXKSgZfLKPhE%3D)

通过创建Job，攻击者可以在Jenkins服务器上创建本地Job并使用它来执行命令，然后在控制台输出中查看结果。允许用户访问构建历史和控制台输出，也可能向任何具有Web控制台访问权限的人泄漏秘密，源代码，密钥等。故而，应检查控制台输出和历史记录，以查找可能被攻击者利用的敏感信息。

为了在具有Job创建权限的Jenkins服务器上执行命令，需要先创建具有给定项目名称的Freestyle项目。

![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/11.jpg)

创建后，可以在Freestyle项目中配置各种选项。为简单起见，请忽略所有选项，然后单击“Add build step”。

![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/12.jpg)

对于该项测试实例，我们将其配置为“执行Windows批处理命令”并运行一些基本命令，包括添加本地管理员帐户。但是，这也可能是在Windows批处理文件（.bat）中运行任何内容。
![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/13.jpg)

单击“save”后，可以通过从Web控制台选择“Build Now”选项来创建新的Freestyle项目。

![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/14.jpg)

创建完成后，可以在控制台输出上查看输出，如下所示。

![](https://ginove.obs.cn-north-1.myhwclouds.com:443/jenkins/15.png?AccessKeyId=O2U7O9Y8RD7QPRJCMG2K&Expires=1540468066&Signature=rh5vb0Wi8%2FiBuYNzcFC6Prgh9s0%3D&x-obs-security-token=gQpjbi1ub3J0aC0xiulRLzrF4nqktOV-pKNHSfUnUO_Y6w5ughv3UkIuny7oBfYWvEGeF0ko2QbCBN87YxAraAX20kkV6CcoBNe1f0YgZrAkqcLsNM6BWjVLfjQE-yPXvGWLmBtoF6QvzijbJ8OhuFOF41nqUyC3wzXx4zWPgSRjXaS1sR4rr0NfmU0TTaOQQGFwyOyuITOTgZ0-yaeVLwXXpjSLrj5sZ2h3--XS8Gd984Okcg6OX0EFER5VUsAInqdKEXkICTJi6lthEkIOwNQm9OUwqJ0YRT_b66HuUPrB55pMvmSG1Do_agzGtytMVLFHEo-cIvZRieVSpPFqAzxMjvevioOAjgJqXAAEZq5DzROyLz3a-P8APf7TlI9RxsocwGBV54mJloLn_Up2efAj4JizUxw-pkoEfJ-mOiXfquAcEwfCc6-8gXfj-Ef38gOtDyAVNtXx9JEOmr8ETlaNYXfhtDZ97iI98oc2fMIJzGviOOaxkg3BJnye8Nk4uO0TA3QIBAekKE9aj1c3Ne8tAPpuFePJOV_VXSBBkFnQAxwa4QqnfLbI54ikljAZgWL_vqwbCEhm-VrEGzPX2qysAQjZTgRL6S5YQwUrVY0wEwE6dXoMHOjZX0dMC4K3PRUXuvRGdfma4ADrFUAV2QqKK33YC5sgWO4akqCt66qEGvcrRGPxE-IuuNxefQtEqtBBJBhRS7nqDszGrfknIGIvukfYBB21pKcw7eY%3D)

请务必注意，由于Jenkins服务器配置为允许匿名创建，因此与Freestyle项目创建关联的用户是未知的。

创建Job后，(受攻击的)可能性与脚本控制台访问几乎相同，但是对于攻击者只能重新配置Job的情况又该当如何呢？这些情况几乎相同，但是，攻击者必须编辑现有Job并调度一个构建。在下面的示例中，我们将重新配置“BackupProject”Freestyle项目以打印存储在凭证插件中的秘密信息。首先，选择一个可修改的项目的“Configure”选项。

![](https://ginove.obs.cn-north-1.myhwclouds.com:443/jenkins/16.png?AccessKeyId=28DFA66NW1XJ5L2XTQZA&Expires=1540468081&Signature=VyNvqAE2MkclqTkeLaJo6Bte%2FvA%3D&x-obs-security-token=gQpjbi1ub3J0aC0xiqRP5J0S6urEUCiYLaP6v6Gwk4WOvNfi-wM47O31Y5CBNtn7t7dNJBB6L1l8TydnRZjSO40YgtJz-yu5NJnQpPqwQ3C9cJ8CVtWdKnnaDgomINRWzLlIMDAQwGbqcVN3hM7xoFr0YP7K7FvQSLpWbK9J04VuyYrHPwSzUvcs9UaGtuJcU3L6dQmz-rEX07J5xDHWjAy6IIzM5wyEgDuHfDB-EcHf76iUIVpdz5BKa-pG-ThC5HRH4zQeNharaxDAZzdP2jewXe_wmjO-yeL3bULgC9VmljoN3cPxQ6mEBwXbRTVxHCoyO182UADhMNyjYpEb9-ji8_mq0MyqUz5KG2ZmGd6rwwUze_fljjyYdnDqynJrmPNK-5InOPAu1sQZHya0RUDa5nJqPWjoTqH3s_QF9_yR1L7v6YfJQk6JqCWpEBk6pNwBiuOJHxSfkLLhbBYJjnaypRcNEKmU3GWzCCN7DoFilj8dBwvxlaYzEkFhCzBxZFeb7avO8uPpFH69i0uxRBq1h3gCyJEyoxr-dDdXtk4R2NfrjcHRoNYaH4GseFas2ZPuZTef5TFKPY4pcCOIffyZGU5NLD7jzhx6s-bQTR8Pdb65u-kwUn4V4NsR1YyVa08XJGtF7gIzdtEZl0GysgF0a34t6a_SHBtaT2xz-FkelDiLQFlVSzO8A-oV2GkmskgPpwFgSFoW_AOHgWkn875TWCUA6JFGImGSOAw%3D)

一旦选定，攻击者可以重新配置`Build Environment`以存储环境变量中的密钥和凭据。然后，可以在Build步骤中使用这些环境变量并输出到文件。此时，攻击者可以将结果输出到全局可访问的userContent文件夹（C://Program Files(x86)/Jenkins/userContent/）。

在Windows系统环境中，使用％字符，而Unix系统则使用$字符来访问变量。

![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/17.jpg)

创建好修改后的项目后，可以在以下位置查看结果： http：//jenkins/userContent/out.txt

![](https://ginove-1252770243.cos.ap-guangzhou.myqcloud.com/jenkins/18.jpg)

[userContent](https://wiki.jenkins.io/display/JENKINS/User+Content)文件夹是一个特殊的文件夹，其中的内容并不受`Overall/Read`权限访问之外的任何访问控制。在攻击者可能为现有的创建项目进行再修改的情况下，这个文件夹可以是存储凭证/秘密控制台输出的一个可行的位置。每次创建后，控制台输出结果（包括凭据/机密）都可以重定向到此文件夹。

### 结论
像Jenkins这样的自动化系统是对手高度重视的目标。管理员花时间保护和审核Jenkins安装的过程显得至关重要，因为这些系统很可能成为网络中攻击者的目标。

为了解决这个问题，CrowdStrike建议Jenkins管理员根据最近攻击者活动的观察结果来注意以下事项：

 1. 没有身份验证，任何人都可以访问Jenkins Web控制台吗？
    - 这包括脚本控制台访问吗？
    - 他们可以查看凭据或创建历史记录吗？
    - 他们可以创建或安排工作吗？
 2. 经过身份验证的用户拥有哪些权限？
    - 这包括脚本控制台访问吗？
    - 他们可以查看凭据或创建历史记录吗？
    - 他们可以创建或安排工作吗？
 3. 是否有敏感信息存储在历史记录或控制台输出中？
 4. Jenkins可以通过互联网访问吗？您的组织是否需要它？
 5. Jenkins服务帐户是否只有为执行其功能所需要的最少权限？
 6. 如何存储凭据？
    - 谁可以访问`credentials.xml`, `master.key`，和`hudson.util.Secret`？
上面的列表并不是保护Jenkins的完整指南，而是依赖于组织。

#### 了解更多：
- 有关CrowdStrike Incident Response，Compromise Assessment or Threat Hunting offerings的更多信息，请访问[CrowdStrike服务页面](https://www.crowdstrike.com/services/)或发送邮件到Service@crowdstrike.com与我们联系。

