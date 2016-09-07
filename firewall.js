//product by chengable www.chengable.com
// 记录内联事件是否被扫描过的 hash map
mCheckMap = {},
// 记录内联事件是否被扫描过的id
mCheckID = 0; 

// 建立白名单,可以自定义自己的正则
var whiteList = [
'^http://www.chengable.com/',
'^http://127.0.0.1/'
];
var whiteListwebsocket = [
'^ws://www.chengable.com/',
'^wss://www.chengable.com/',
'^wss://127.0.0.1/',
'^ws://127.0.0.1/'
];
// 建立黑名单
var blackList = [
'192.168.1.0'
];

// 建立关键词黑名单，可以添加你自己的关键词,不同的标签黑名单不同，适应各种情况
var wordblackliston = [

'javascript',
'eval',
'alert',
'function',
'src='
];
var jswordblacklist = [

'javascript',
'eval',
'alert'
];
var wordblacklistDocumetnWrite = [
'javascript',
'eval',
'script',
'iframe',
'alert',
'src='
];
var wordblacklistinnerHTML = [
'alert',
'javascript',
'eval',
'script',
'iframe'
];

//正则判断内容是否有害，可以在这里定义你自己的过滤规则
function blackregmatch(wordblacklist,code)
{
	var reglen=wordblacklist.length;
	for (i=0;i<reglen;i++)
	{
		var reg=new RegExp(wordblacklist[i], 'i');
		if (reg.test(code))
		{
			return true;
		}
	}
	return false;
	
}
//启动内联函数(on...)拦截
function begin_interception()
{
	var i=0;
	for (var obj in document)
	{
		
		
		if (/^on.*/.test(obj))
		{
			eventname=obj;
			eventid=i++;
			hookonevent(eventname,eventid);
		}
	}
}

function hookonevent(eventname,eventid)
{
	var isClick = (eventname == 'onclick');
	document.addEventListener(eventname.substr(2), function(e) {
        scanElement(e.target,eventname,eventid,isClick);
    }, true);
	
}

//扫描on事件
function scanElement(elem,eventname,eventid,isClick)
{
	
	
	var code = "",hash = 0;
	var flag=elem['isscan'];
	if(!flag)
	{
		flag=elem['isscan'] = ++mCheckID;
	}
	
	hash = (flag << 8) | eventid;
	
	if (hash in mCheckMap) 
	{
	  return;
	}
	//给即将要扫描的时间加上hash标记，下次就直接跳过了
	mCheckMap[hash] = true;

	// 非元素节点就直接返回了
	if (elem.nodeType != Node.ELEMENT_NODE) 
	{
	  return;
	}
	//开始扫描on事件
	
	if (elem[eventname]) 
	{
		code = elem.getAttribute(eventname);
		
		if (code && blackregmatch(wordblackliston, code)) 
		{
			// 注销事件
			elem[eventname] = null;
			console.log('拦截可疑事件，tag:' + elem.tagName+'，event:'+eventname+'，code:'+code);
			//Report('拦截可疑内联事件', code);
			
		}
	}
	if (elem.tagName == 'A' && elem.protocol == 'javascript:' && eventname=='onclick') 
	{
		
		var code = elem.href;
		if (blackregmatch(wordblackliston, code)) 
		{
			// 注销代码
			elem.href = 'javascript:void(0)';
			console.log('拦截可疑模块，tag:' + elem.tagName+'，event:'+eventname+'，code:'+code);
			//Report('拦截可疑javascript:代码', code);
		}
	}
	scanElement(elem.parentNode);

}
//静态脚本拦截
function interceptionStaticScript() 
{
    // MutationObserver 的不同兼容性写法
    var MutationObserver = window.MutationObserver || window.WebKitMutationObserver || window.MozMutationObserver;

    // 该构造函数用来实例化一个新的 Mutation 观察者对象
    // Mutation 观察者对象能监听在某个范围内的 DOM 树变化
    var observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
		  begininterceptionstatic(mutation)
       });
    });

    // 传入目标节点和观察选项
    // 如果 target 为 document 或者 document.documentElement
    // 则当前文档中所有的节点添加与删除操作都会被观察到
    observer.observe(document, {
      subtree: true,
      childList: true
    });
}
//静态脚本检测拦截函数
function begininterceptionstatic(mutation)
{
	// 返回被添加的节点,或者为null.
	var nodes = mutation.addedNodes;

	// 逐个遍历
	for (var i = 0; i < nodes.length; i++)
	{
		var node = nodes[i];

		// 扫描 script 与 iframe
		if (node.tagName === 'SCRIPT' || node.tagName === 'IFRAME') 
		{
			// 拦截到可疑iframe
			if (node.tagName === 'IFRAME' && node.srcdoc)
			{
			  node.parentNode.removeChild(node);
			  console.log('拦截到危险iframe', node.srcdoc);
			  //Report('拦截到危险iframe', node.srcdoc);

			}
			else if (node.src) 
			{
				// 只放行白名单
				if (!whileListMatch(whiteList, node.src))
				{

					node.parentNode.removeChild(node);
					// 上报
					console.log('拦截可疑静态脚本:', node.src);
					//Report('拦截可疑静态脚本', node.src);
				}
			}
			else if (blackregmatch(jswordblacklist,node.textContent))
			{
				node.parentNode.removeChild(node);
				console.log('拦截可疑静态脚本：'+node.textContent);
				
			}
		}
	}

}
//src属性的白名单
function whileListMatch(whiteList,code)
{
	var wlen=whiteList.length;
	for (i=0;i<wlen;i++)
	{
		var reg=new RegExp(whiteList[i]);
		if (reg.test(code))
		{
			return true;
		}
	}
	return false;
}

function interceptionDynamicScript(window)
{
	
	installHook(window);
	
}

function interception_src_inner()
{
	//拦截动态生成src属性
	var raw_setter = HTMLScriptElement.prototype.__lookupSetter__('src');
	HTMLScriptElement.prototype.__defineSetter__('src', function(url) {
	if (!whileListMatch(whiteList,url)) 
	{
		console.log('拦截可疑src动态脚本：'+url);
		return ;
	}
	raw_setter.call(this, url);
    });
	
	//拦截利用innerHTML动态生成恶意代码
	var raw_setter = HTMLScriptElement.prototype.__lookupSetter__('innerHTML');
	HTMLScriptElement.prototype.__defineSetter__('innerHTML', function(url) {
	if (blackregmatch(wordblacklistinnerHTML, url))
	{
		console.log('拦截可疑innerHTML动态脚本：'+url);
		return ;
	}
	raw_setter.call(this, url);
    });
}


function resetCreateElement()
{
	var old_ce = Document.prototype.createElement;

	Document.prototype.createElement = function() 
	{
		// 调用原生函数
		var element = old_ce.apply(this, arguments);
		// 为脚本元素安装属性钩子

		element.__defineSetter__('src', function(url) 
		{
			if (!whileListMatch(whiteList,url)) 
			{
				console.log('拦截可疑CreateElement动态脚本：'+url);
				return ;
			}
		});
		

		// 返回元素实例
		return element;
	};
}


function resetDocumentWrite(window) 
{
	var old_write = window.document.write;

	window.document.write = function(string) 
	{
		if (blackregmatch(wordblacklistDocumetnWrite, string)) 
		{
			console.log('拦截可疑DocumentWrite动态脚本:', string);
			//Report('拦截可疑document-write', string);
			return;
		}

		// 调用原始接口
		old_write.apply(document, arguments);
	}
}


function resetSetAttribute(window) 
{
	// 保存原有接口
	var old_setAttribute = window.Element.prototype.setAttribute;

	// 重写 setAttribute 接口
	window.Element.prototype.setAttribute = function(name, value) 
	{

	  // 拦截规则
		if (/^src$/i.test(name)) 
		{

			if (!whileListMatch(whiteList,value)) 
			{
				console.log('拦截可疑SetAttribute动态模块，属性:'+name+'，值:'+value);
				return;
			}
		}
		else if (blackregmatch(wordblackliston, value))
		{
			console.log('拦截可疑SetAttribute动态模块，属性:'+name+'，值:'+ value);
			return;
		}

		// 调用原始接口
		old_setAttribute.apply(this, arguments);
	};
}


function installHook(window)
{
	interception_src_inner();//拦截src和innerHTML属性
	resetCreateElement();//重写createElement()拦截src属性，这里其实和上面重复了，可以去掉
	resetSetAttribute(window);// 重写当前 window 窗口的 setAttribute 属性
	resetDocumentWrite(window);// 重写当前 window 窗口的 document.Write 属性
	ajaxlook(this.XMLHttpRequest);//监听ajax请求
	websocket_look(window);//监听websocket请求
	postmsg_look(window);//监听postMessage请求

	// MutationObserver 的不同兼容性写法
	var MutationObserver = window.MutationObserver || window.WebKitMutationObserver || window.MozMutationObserver;

	// 该构造函数用来实例化一个新的 Mutation 观察者对象
	// Mutation 观察者对象能监听在某个范围内的 DOM 树变化
	var observer = new MutationObserver(function(mutations) 
	{
		mutations.forEach(function(mutation) 
		{
			// 返回被添加的节点,或者为null.
			var nodes = mutation.addedNodes;

			// 逐个遍历
			for (var i = 0; i < nodes.length; i++) 
			{
				var node = nodes[i];

				// 给生成的 iframe 里环境也装上重写的钩子
				if (node.tagName == 'IFRAME') 
				{
					installHook(node.contentWindow);
				}
			}
		});
	});

	observer.observe(document, {
	  subtree: true,
	  childList: true
	});
}



function lockCallAndApply() 
{
		// 锁住 call
		Object.defineProperty(Function.prototype, 'call', {
		value: Function.prototype.call,
		// 当且仅当仅当该属性的 writable 为 true 时，该属性才能被赋值运算符改变
		writable: false,
		// 当且仅当该属性的 configurable 为 true 时，该属性才能够被改变，也能够被删除
		configurable: false,
		enumerable: true
		});
		// 锁住 apply
		Object.defineProperty(Function.prototype, 'apply', {
		value: Function.prototype.apply,
		writable: false,
		configurable: false,
		enumerable: true
		});
}


function ajaxlook(objectOfXMLHttpRequest) 
{  
    // http://stackoverflow.com/questions/3596583/javascript-detect-an-ajax-event  

      
	var s_ajaxListener = new Object();  
	s_ajaxListener.tempOpen = objectOfXMLHttpRequest.prototype.open;  
	s_ajaxListener.tempSend = objectOfXMLHttpRequest.prototype.send;  

      
	objectOfXMLHttpRequest.prototype.open = function(a,b) 
	{
		
		if (!a) var a=' ';  
		if (!b) var b=' ';  
		var open_method=a;
		var open_url=b;
		
		if (!whileListMatch(whiteList,open_url))
		{
			console.log('拦截可疑ajax请求'+open_method+':'+open_url);
			return ;
			
		}
		s_ajaxListener.tempOpen.apply(this, arguments);  
       
    }  
      
}



function websocket_look(window)
{
	var raw_class = window.WebSocket;
	window.WebSocket = function WebSocket(url, arg) 
	{
		if(!whileListMatch(whiteListwebsocket,url))
		{
			console.log('拦截可疑WebSocket 请求' + url);
			return ;
		}

		

		var ins = new raw_class(url, arg);
		ins.constructor = WebSocket;
		return ins;
	};

}



function postmsg_look(window)
{
	var old_postMessage = window.postMessage;
	window.postMessage = function postMessage(data, url) 
	{
		if (!whileListMatch(whiteList,url))
		{
			console.log('拦截可疑postMessage请求，地址：' + url+'，数据：'+data);
			return;
		}
		
		old_postMessage.apply(this,arguments);
	};


}




begin_interception();//恶意事件拦截
interceptionStaticScript();//静态脚本拦截
interceptionDynamicScript(window);//动态脚本拦截,以及向非白名单站发送请求拦截
//ajaxlook(this.XMLHttpRequest);//拦截向恶监听意外部发送的ajax请求，同源策略是可以发不能收，所以发送还是要监听