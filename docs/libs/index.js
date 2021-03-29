/**
 * Docsify config
 */
//  gitalkConfig = {
//     clientID: '5a7b7fa143ac3300a618',
//     clientSecret: 'a3faa58ae9c1594756a8b46793bd0097b1be8455',
//     repo:'he0xwhale.github.io',
//     owner:"he0xwhale",
//     admin: ['he0xwhale'],
//     pagerDirection: "last",
//     perPage: 20,
//     title: location.hash.match(/#(.*?)([?]|$)/)[1],
//     id: location.hash.match(/#(.*?)([?]|$)/)[1],
//     // facebook-like distraction free mode
//     distractionFreeMode: false
//  }
//  window.onhashchange = function(event){
//     if(event.newURL.split('?')[0] !== event.oldURL .split('?')[0]) {
//       location.reload()
//     }
//   }

window.$docsify = {
    name: 'he0xwhale\'s wikiblog',
    repo: '',
    // logo:'/_media/he0x_whale_v0.3.png',
    loadSidebar: true,
    // loadNavbar: true,
    coverpage:true,
    // themeColor:'#25798A',
    maxLevel:6,
    subMaxLevel: 6,
    topMargin: 20,
    toc:{
      scope: '.markdown-section',
      headdings:'h1,h2,h3,h4',
      title:'快速跳转'
    },
    //搜索
    search: 'auto',
    placeholder:{
      '/zh-cn/':'搜索',
      '/':'Type to search'
    },
    noData: {
      '/zh-cn/': '找不到结果',
      '/': 'No Results'
      },
      pagination: {
    previousText: '上一章节',
    nextText: '下一章节',
    crossChapter: true,
    crossChapterText: true,
},
// auto2top:true,
// routerMode: 'history',
//code
copyCode: {
    // buttonText : 'buttonText:String',
    // errorText : 'errorText:String',
    // successText: 'successText:String'
    buttonText: {
        '/zh-cn/': '点击复制',
        '/ru/': 'Скопировать в буфер обмена',
        '/de-de/': 'Klicken Sie zum Kopieren',
        '/es/': 'Haga clic para copiar',
        '/': 'Copy to clipboard'
    },
    errorText: {
        '/zh-cn/': '错误',
        '/ru/': 'ошибка',
        '/': 'Error'
    },
    successText: {
        '/zh-cn/': '复制',
        '/ru/': 'Скопировано',
        '/de-de/': 'Kopiert',
        '/es/': 'Copiado',
        '/': 'Copied'
    }
},
// plugins: [
//     function(hook, vm) {
//     //   hook.beforeEach(function(html) {
//     //     var url =
//     //       "https://github.com/he0xwhale/he0xwhale.github.io/blob/main/" +
//     //       vm.route.file;
//     //     var editHtml = "[📝 EDIT DOCUMENT](" + url + ")\n";

//     //     return editHtml + html;
//     //   });

//       hook.doneEach(function() {
//         var label, domObj, main, divEle, gitalk;
//         label = vm.route.path.split("/").pop();
//         domObj = Docsify.dom;
//         main = domObj.getNode("#main");

//         /**
//          * render gittalk
//          */
//         if (vm.route.path.includes("zh-cn")) {
//           gitalkConfig.language = "zh-CN";
//         }
//         Array.apply(
//           null,
//           document.querySelectorAll("div.gitalk-container")
//         ).forEach(function(ele) {
//           ele.remove();
//         });
//         divEle = domObj.create("div");
//         divEle.id = "gitalk-container-" + label;
//         divEle.className = "gitalk-container";
//         divEle.style = "width: " + main.clientWidth + "px; margin: 0 auto 20px;";
//         domObj.appendTo(domObj.find(".content"), divEle);
//         gitalk = new Gitalk(
//           Object.assign(gitalkConfig, { id: !label ? "home" : label })
//         );
//         gitalk.render("gitalk-container-" + label);
//       });
 
//     }
//   ]
  }