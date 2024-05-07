/* Copyright (c) 2015-2019, Chandan B.N.
 *
 * Copyright (c) 2019, FIRST.ORG, INC
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*

CVSSjs Version 0.1 beta

Usage:
    craete an html element with an id for eg.,
    <div id="cvssboard"></div>

    // create a new instance of CVSS calculator:
    var c = new CVSS("cvssboard");

    // create a new instance of CVSS calculator with some event handler callbacks
    var c = new CVSS("cvssboard", {
                onchange: function() {....} //optional
                onsubmit: function() {....} //optional
                }

    // set a vector
    c.set('AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L');

    //get the value
    c.get() returns an object like:

    {
        score: 4.3,
        vector: 'AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L'
    }

*/
var CVSS = function(id, options) {
    this.options = options;
    this.wId = id;
    var e = function(tag) {
        return document.createElement(tag);
    };

    // 基础组
    this.bg = {
        AV: '攻击途径',
        AC: '攻击复杂度',
        PR: '权限要求',
        UI: '用户交互',
        S: '作用域',
        C: '机密性影响',
        I: '完整性影响',
        A: '可用性影响'
    };

    // 基础度量
    this.bm = {
        AV: {
            N: {
                l: '网络',
                d: "<b>最差：</b> 可利用的组件绑定到网络堆栈，可能攻击者的范围延伸到其他选项列表之外，包括整个互联网。这种漏洞通常被称为“远程可利用”，可以被认为是攻击在协议级别跨越一个或多个网络跳跃（例如，跨越一个或多个路由器）。"
            },
            A: {
                l: '相邻',
                d: "<b>更差：</b> 可利用的组件绑定到网络堆栈，但攻击仅限于逻辑上相邻的拓扑。这可能意味着攻击必须从相同的共享物理（例如，蓝牙或IEEE 802.11）或逻辑（例如，本地IP子网）网络，或从受限的管理域内部（例如，MPLS，安全VPN到管理网络区域）。 相邻攻击的一个例子是ARP（IPv4）或邻居发现（IPv6）洪泛导致本地LAN段上的服务拒绝。"
            },
            L: {
                l: '本地',
                d: "<b>不好：</b> 可利用的组件未绑定到网络堆栈，攻击者的路径是通过读取/写入/执行功能。可能是：<ul><li>攻击者通过本地访问目标系统（例如，键盘，控制台）或远程访问（例如，SSH）来利用漏洞；</li><li>或攻击者依赖于其他人的用户交互来执行利用漏洞所需的操作（例如，使用社会工程技术欺骗合法用户打开恶意文档）。 </li></ul>"
            },
            P: {
                l: '物理',
                d: "<b>不好：</b> 攻击者需要物理接触或操纵可利用的组件。物理交互可能是短暂的（例如，恶意女佣攻击）或持久的。这种攻击的一个例子是冷启动攻击，攻击者在物理访问目标系统后获得磁盘加密密钥。其他示例包括通过FireWire/USB直接内存访问（DMA）进行的外围攻击。"
            }
        },
        AC: {
            L: {
                l: '低',
                d: "<b>最差：</b> 不会出现特殊的访问条件或特殊情况。攻击者可以期望在攻击可利用组件时取得重复成功。"
            },
            H: {
                l: '高',
                d: "<b>不好：</b> 成功的攻击取决于攻击者无法控制的条件。也就是说，成功的攻击不能随意进行，而需要攻击者在攻击可利用组件之前投入一定量的努力进行准备或执行。"
            }
        },
        PR: {
            N: {
                l: '无',
                d: "<b>最差：</b> 攻击者在攻击之前未经授权，因此不需要访问可利用系统的任何设置或文件即可执行攻击。"
            },
            L: {
                l: '低',
                d: "<b>更差：</b> 攻击者需要具有基本用户功能的权限，这些权限通常只能影响用户拥有的设置和文件。或者，低权限的攻击者有权访问仅限制的资源。"
            },
            H: {
                l: '高',
                d: "<b>不好：</b> 攻击者需要具有重要（例如，管理）对可利用组件的控制权限，允许访问组件范围内的设置和文件。"
            }
        },
        UI: {
            N: {
                l: '无',
                d: "<b>最差：</b> 可利用系统可以在没有任何用户交互的情况下利用。"
            },
            R: {
                l: '必需',
                d: "<b>不好：</b> 此漏洞的成功利用需要用户在漏洞利用之前采取某些操作。例如，只有在系统管理员安装应用程序时才可能成功利用漏洞。"
            }
        },

        S: {
            C: {
                l: '变化',
                d: "<b>最差：</b> 被利用的漏洞可能会影响安全范围管理的资源。在这种情况下，受影响的组件和受影响的组件是不同的，并由不同的安全管理者管理。"
            },
            U: {
                l: '固定',
                d: "<b>不好：</b> 被利用的漏洞只能影响由相同的安全管理者管理的资源。在这种情况下，受影响的组件和受影响的组件要么相同，要么由同一安全管理者管理。"
            }
        },
        C: {
            H: {
                l: '高',
                d: "<b>最差：</b> 存在机密性的完全丧失，导致受影响组件中的所有资源都被泄露给攻击者。或者，仅获得对某些受限信息的访问，但所披露的信息产生了直接、严重的影响。例如，攻击者窃取管理员的密码，或者窃取Web服务器的私有加密密钥。"
            },
            L: {
                l: '低',
                d: "<b>不好：</b> 存在机密性的某些丧失。获得对某些受限信息的访问，但攻击者无法控制获取的信息，或者损失的数量或种类是有限的。信息泄露不会对受影响的组件造成直接、严重的损失。"
            },
            N: {
                l: '无',
                d: "<b>好：</b> 在受影响的组件内部没有机密性的丧失。"
            }
        },
        I: {
            H: {
                l: '高',
                d: "<b>最差：</b> 完整性的完全丧失或保护的完全丧失。例如，攻击者能够修改受受影响组件保护的任何/所有文件。或者，只能修改某些文件，但恶意修改会对受影响组件产生直接、严重的后果。"
            },
            L: {
                l: '低',
                d: "<b>不好：</b> 数据的修改是可能的，但攻击者无法控制修改的后果，或者修改的数量有限。数据修改不会对受影响组件产生直接、严重的影响。"
            },
            N: {
                l: '无',
                d: "<b>好：</b> 在受影响的组件内部没有完整性的丧失。"
            }
        },
        A: {
            H: {
                l: '高',
                d: "<b>最差：</b> 存在可用性的完全丧失，导致攻击者能够完全拒绝对受影响组件中资源的访问；这种丧失是持续的（当攻击者继续发起攻击时）或持久的（条件在攻击完成后仍然存在）。或者，攻击者有能力拒绝某些可用性，但可用性的丧失对受影响组件产生直接、严重的后果（例如，攻击者无法中断现有连接，但可以阻止新连接；攻击者可以重复利用一个漏洞，每次成功攻击后，泄漏的内存量都很小，但重复利用后导致服务完全不可用）。"
            },
            L: {
                l: '低',
                d: "<b>不好：</b> 性能降低或资源可用性中断。即使可以重复利用漏洞，攻击者也无法完全拒绝合法用户的服务。受影响组件的资源要么在所有时间内部分可用，要么在某些时间内完全可用，但总体上不会对受影响组件产生直接、严重的后果。"
            },
            N: {
                l: '无',
                d: "<b>好：</b> 在受影响的组件内部没有可用性的影响。"
            }
        }
    };

    this.bme = {};
    this.bmgReg = {
        AV: 'NALP',
        AC: 'LH',
        PR: 'NLH',
        UI: 'NR',
        S: 'CU',
        C: 'HLN',
        I: 'HLN',
        A: 'HLN'
    };
    this.bmoReg = {
        AV: 'NALP',
        AC: 'LH',
        C: 'C',
        I: 'C',
        A: 'C'
    };
    var s, f, dl, g, dd, l;
    this.el = document.getElementById(id);
    this.el.appendChild(s = e('style'));
    s.innerHTML = '';
    this.el.appendChild(f = e('form'));
    f.className = 'cvssjs';
    this.calc = f;
    for (g in this.bg) {
        f.appendChild(dl = e('dl'));
        dl.setAttribute('class', g);
        var dt = e('dt');
        dt.innerHTML = this.bg[g];
        dl.appendChild(dt);
        for (s in this.bm[g]) {
            dd = e('dd');
            dl.appendChild(dd);
            var inp = e('input');
            inp.setAttribute('name', g);
            inp.setAttribute('value', s);
            inp.setAttribute('id', id + g + s);
            inp.setAttribute('class', g + s);
            //inp.setAttribute('ontouchstart', '');
            inp.setAttribute('type', 'radio');
            this.bme[g + s] = inp;
            var me = this;
            inp.onchange = function() {
                me.setMetric(this);
            };
            dd.appendChild(inp);
            l = e('label');
            dd.appendChild(l);
            l.setAttribute('for', id + g + s);
            l.appendChild(e('i')).setAttribute('class', g + s);
            l.appendChild(document.createTextNode(this.bm[g][s].l + ' '));
            dd.appendChild(e('small')).innerHTML = this.bm[g][s].d;
        }
    }
    //f.appendChild(e('hr'));
    f.appendChild(dl = e('dl'));
    dl.innerHTML = '<dt>严重性&sdot;分数&sdot;向量</dt>';
    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';
    l.appendChild(this.severity = e('span'));
    this.severity.className = 'severity';
    l.appendChild(this.score = e('span'));
    this.score.className = 'score';
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.vector = e('a'));
    this.vector.className = 'vector';
    this.vector.innerHTML = 'CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_';

    if (options.onsubmit) {
        f.appendChild(e('hr'));
        this.submitButton = f.appendChild(e('input'));
        this.submitButton.setAttribute('type', 'submit');
        this.submitButton.onclick = options.onsubmit;
    }
};

CVSS.prototype.severityRatings = [{
    name: "无",
    bottom: 0.0,
    top: 0.0
}, {
    name: "低",
    bottom: 0.1,
    top: 3.9
}, {
    name: "中",
    bottom: 4.0,
    top: 6.9
}, {
    name: "高",
    bottom: 7.0,
    top: 8.9
}, {
    name: "严重",
    bottom: 9.0,
    top: 10.0
}];

CVSS.prototype.severityRating = function(score) {
    var i;
    var severityRatingLength = this.severityRatings.length;
    for (i = 0; i < severityRatingLength; i++) {
        if (score >= this.severityRatings[i].bottom && score <= this.severityRatings[i].top) {
            return this.severityRatings[i];
        }
    }
    return {
        name: "?",
        bottom: '未',
        top: '定义'
    };
};

CVSS.prototype.valueofradio = function(e) {
    for (var i = 0; i < e.length; i++) {
        if (e[i].checked) {
            return e[i].value;
        }
    }
    return null;
};

CVSS.prototype.calculate = function() {
    var cvssVersion = "3.1";
    var exploitabilityCoefficient = 8.22;
    var scopeCoefficient = 1.08;

    // Define associative arrays mapping each metric value to the constant used in the CVSS scoring formula.
    var Weight = {
        AV: {
            N: 0.85,
            A: 0.62,
            L: 0.55,
            P: 0.2
        },
        AC: {
            L: 0.77,
            H: 0.44
        },
        PR: {
            N: 0.85,
            L: 0.62,
            H: 0.27
        },
        UI: {
            N: 0.85,
            R: 0.62
        },
        S: {
            U: 6.42,
            C: 7.52
        },
        C: {
            N: 0,
            L: 0.22,
            H: 0.56
        },
        I: {
            N: 0,
            L: 0.22,
            H: 0.56
        },
        A: {
            N: 0,
            L: 0.22,
            H: 0.56
        }
    };

    var p;
    var val = {},
        metricWeight = {};
    try {
        for (p in this.bg) {
            val[p] = this.valueofradio(this.calc.elements[p]);
            if (typeof val[p] === "undefined" || val[p] === null) {
                return "?";
            }
            metricWeight[p] = Weight[p][val[p]];
        }
    } catch (err) {
        return err; // TODO: need to catch and return sensible error value & do a better job of specifying *which* parm is at fault.
    }
    //
    // CALCULATE THE CVSS BASE SCORE
    //
    var roundUp1 = function Roundup(input) {
        var int_input = Math.round(input * 100000);
        if (int_input % 10000 === 0) {
            return int_input / 100000
        } else {
            return (Math.floor(int_input / 10000) + 1) / 10
        }
    };
    try {
        var baseScore, impactSubScore, impact, exploitability;
        var impactSubScoreMultiplier = (1 - ((1 - metricWeight.C) * (1 - metricWeight.I) * (1 - metricWeight.A)));
        if (val.S === 'U') {
            impactSubScore = metricWeight.S * impactSubScoreMultiplier;
        } else {
            impactSubScore = metricWeight.S * (impactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(impactSubScoreMultiplier - 0.02, 15);
        }
        var exploitabalitySubScore = exploitabilityCoefficient * metricWeight.AV * metricWeight.AC * metricWeight.PR * metricWeight.UI;
        if (impactSubScore <= 0) {
            baseScore = 0;
        } else {
            if (val.S === 'U') {
                baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore), 10));
            } else {
                baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore) * scopeCoefficient, 10));
            }
        }

        return baseScore.toFixed(1);
    } catch (err) {
        return err;
    }
};

CVSS.prototype.get = function() {
    return {
        score: this.score.innerHTML,
        vector: this.vector.innerHTML
    };
};

CVSS.prototype.setMetric = function(a) {
    var vectorString = this.vector.innerHTML;
    if (/AV:.\/AC:.\/PR:.\/UI:.\/S:.\/C:.\/I:.\/A:./.test(vectorString)) {} else {
        vectorString = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';
    }
    this.vector.innerHTML = vectorString.replace(new RegExp(a.getAttribute('name') + ':.'), a.getAttribute('name') + ':' + a.value);
    this.score.innerHTML = this.calculate();
    var severity = this.severityRating(parseFloat(this.score.innerHTML));
    this.severity.innerHTML = severity.name;
    this.severity.className = 'severity ' + severity.name.toLowerCase();
};

CVSS.prototype.import = function(vectorString) {
    if (typeof vectorString !== 'undefined') {
        this.vector.innerHTML = vectorString;
    }
    var vectorArray = this.vector.innerHTML.split('/');
    for (var i in vectorArray) {
        var paramValue = vectorArray[i].split(':');
        if (paramValue.length === 2) {
            this.bme[paramValue[0] + paramValue[1]].checked = true;
        }
    }
    this.score.innerHTML = this.calculate();
    var severity = this.severityRating(parseFloat(this.score.innerHTML));
    this.severity.innerHTML = severity.name;
    this.severity.className = 'severity ' + severity.name.toLowerCase();
};

CVSS.prototype.clear = function() {
    var name, elements;
    elements = this.calc.getElementsByTagName('input');
    for (var i = 0, len = elements.length; i < len; i++) {
        if (elements[i].type === 'radio') {
            elements[i].checked = false;
        }
    }
    this.score.innerHTML = '';
    this.vector.innerHTML = 'CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_';
    this.severity.innerHTML = '';
    this.severity.className = 'severity';
};




// var CVSS = function(id, options) {
//     this.options = options;
//     this.wId = id;
//     var e = function(tag) {
//         return document.createElement(tag);
//     };

//     // Base Group
//     this.bg = {
//         AV: 'Attack Vector',
//         AC: 'Attack Complexity',
//         PR: 'Privileges Required',
//         UI: 'User Interaction',
//         S: 'Scope',
//         C: 'Confidentiality',
//         I: 'Integrity',
//         A: 'Availability'
//     };

//     // Base Metrics
//     this.bm = {
//         AV: {
//             N: {
//                 l: 'Network',
//                 d: "<b>Worst:</b> The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers)."
//             },
//             A: {
//                 l: 'Adjacent',
//                 d: "<b>Worse:</b> The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment."
//             },
//             L: {
//                 l: 'Local',
//                 d: "<b>Bad:</b> The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: <ul><li>the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH);</li><li>or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).</li></ul>"
//             },
//             P: {
//                 l: 'Physical',
//                 d: "<b>Bad:</b> The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief (e.g., evil maid attack) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA)."
//             }
//         },
//         AC: {
//             L: {
//                 l: 'Low',
//                 d: "<b>Worst:</b> Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component."
//             },
//             H: {
//                 l: 'High',
//                 d: "<b>Bad:</b> A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected."
//             }
//         },
//         PR: {
//             N: {
//                 l: 'None',
//                 d: "<b>Worst:</b> The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the the vulnerable system to carry out an attack."
//             },
//             L: {
//                 l: 'Low',
//                 d: "<b>Worse</b> The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources."
//             },
//             H: {
//                 l: 'High',
//                 d: "<b>Bad:</b> The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files."
//             }
//         },
//         UI: {
//             N: {
//                 l: 'None',
//                 d: "<b>Worst:</b> The vulnerable system can be exploited without interaction from any user."
//             },
//             R: {
//                 l: 'Required',
//                 d: "<b>Bad:</b> Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator."
//             }
//         },

//         S: {
//             C: {
//                 l: 'Changed',
//                 d: "<b>Worst:</b> An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities."
//             },
//             U: {
//                 l: 'Unchanged',
//                 d: "<b>Bad:</b> An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority."
//             }
//         },
//         C: {
//             H: {
//                 l: 'High',
//                 d: "<b>Worst:</b> There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server."
//             },
//             L: {
//                 l: 'Low',
//                 d: "<b>Bad:</b> There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component."
//             },
//             N: {
//                 l: 'None',
//                 d: "<b>Good:</b> There is no loss of confidentiality within the impacted component."
//             }
//         },
//         I: {
//             H: {
//                 l: 'High',
//                 d: "<b>Worst:</b> There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component."
//             },
//             L: {
//                 l: 'Low',
//                 d: "<b>Bad:</b> Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component."
//             },
//             N: {
//                 l: 'None',
//                 d: "<b>Good:</b> There is no loss of integrity within the impacted component."
//             }
//         },
//         A: {
//             H: {
//                 l: 'High',
//                 d: "<b>Worst:</b> There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable)."
//             },
//             L: {
//                 l: 'Low',
//                 d: "<b>Bad:</b> Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component."
//             },
//             N: {
//                 l: 'None',
//                 d: "<b>Good:</b> There is no impact to availability within the impacted component."
//             }
//         }
//     };

//     this.bme = {};
//     this.bmgReg = {
//         AV: 'NALP',
//         AC: 'LH',
//         PR: 'NLH',
//         UI: 'NR',
//         S: 'CU',
//         C: 'HLN',
//         I: 'HLN',
//         A: 'HLN'
//     };
//     this.bmoReg = {
//         AV: 'NALP',
//         AC: 'LH',
//         C: 'C',
//         I: 'C',
//         A: 'C'
//     };
//     var s, f, dl, g, dd, l;
//     this.el = document.getElementById(id);
//     this.el.appendChild(s = e('style'));
//     s.innerHTML = '';
//     this.el.appendChild(f = e('form'));
//     f.className = 'cvssjs';
//     this.calc = f;
//     for (g in this.bg) {
//         f.appendChild(dl = e('dl'));
//         dl.setAttribute('class', g);
//         var dt = e('dt');
//         dt.innerHTML = this.bg[g];
//         dl.appendChild(dt);
//         for (s in this.bm[g]) {
//             dd = e('dd');
//             dl.appendChild(dd);
//             var inp = e('input');
//             inp.setAttribute('name', g);
//             inp.setAttribute('value', s);
//             inp.setAttribute('id', id + g + s);
//             inp.setAttribute('class', g + s);
//             //inp.setAttribute('ontouchstart', '');
//             inp.setAttribute('type', 'radio');
//             this.bme[g + s] = inp;
//             var me = this;
//             inp.onchange = function() {
//                 me.setMetric(this);
//             };
//             dd.appendChild(inp);
//             l = e('label');
//             dd.appendChild(l);
//             l.setAttribute('for', id + g + s);
//             l.appendChild(e('i')).setAttribute('class', g + s);
//             l.appendChild(document.createTextNode(this.bm[g][s].l + ' '));
//             dd.appendChild(e('small')).innerHTML = this.bm[g][s].d;
//         }
//     }
//     //f.appendChild(e('hr'));
//     f.appendChild(dl = e('dl'));
//     dl.innerHTML = '<dt>Severity&sdot;Score&sdot;Vector</dt>';
//     dd = e('dd');
//     dl.appendChild(dd);
//     l = dd.appendChild(e('label'));
//     l.className = 'results';
//     l.appendChild(this.severity = e('span'));
//     this.severity.className = 'severity';
//     l.appendChild(this.score = e('span'));
//     this.score.className = 'score';
//     l.appendChild(document.createTextNode(' '));
//     l.appendChild(this.vector = e('a'));
//     this.vector.className = 'vector';
//     this.vector.innerHTML = 'CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_';

//     if (options.onsubmit) {
//         f.appendChild(e('hr'));
//         this.submitButton = f.appendChild(e('input'));
//         this.submitButton.setAttribute('type', 'submit');
//         this.submitButton.onclick = options.onsubmit;
//     }
// };

// CVSS.prototype.severityRatings = [{
//     name: "None",
//     bottom: 0.0,
//     top: 0.0
// }, {
//     name: "Low",
//     bottom: 0.1,
//     top: 3.9
// }, {
//     name: "Medium",
//     bottom: 4.0,
//     top: 6.9
// }, {
//     name: "High",
//     bottom: 7.0,
//     top: 8.9
// }, {
//     name: "Critical",
//     bottom: 9.0,
//     top: 10.0
// }];

// CVSS.prototype.severityRating = function(score) {
//     var i;
//     var severityRatingLength = this.severityRatings.length;
//     for (i = 0; i < severityRatingLength; i++) {
//         if (score >= this.severityRatings[i].bottom && score <= this.severityRatings[i].top) {
//             return this.severityRatings[i];
//         }
//     }
//     return {
//         name: "?",
//         bottom: 'Not',
//         top: 'defined'
//     };
// };

// CVSS.prototype.valueofradio = function(e) {
//     for (var i = 0; i < e.length; i++) {
//         if (e[i].checked) {
//             return e[i].value;
//         }
//     }
//     return null;
// };

// CVSS.prototype.calculate = function() {
//     var cvssVersion = "3.1";
//     var exploitabilityCoefficient = 8.22;
//     var scopeCoefficient = 1.08;

//     // Define associative arrays mapping each metric value to the constant used in the CVSS scoring formula.
//     var Weight = {
//         AV: {
//             N: 0.85,
//             A: 0.62,
//             L: 0.55,
//             P: 0.2
//         },
//         AC: {
//             H: 0.44,
//             L: 0.77
//         },
//         PR: {
//             U: {
//                 N: 0.85,
//                 L: 0.62,
//                 H: 0.27
//             },
//             // These values are used if Scope is Unchanged
//             C: {
//                 N: 0.85,
//                 L: 0.68,
//                 H: 0.5
//             }
//         },
//         // These values are used if Scope is Changed
//         UI: {
//             N: 0.85,
//             R: 0.62
//         },
//         S: {
//             U: 6.42,
//             C: 7.52
//         },
//         C: {
//             N: 0,
//             L: 0.22,
//             H: 0.56
//         },
//         I: {
//             N: 0,
//             L: 0.22,
//             H: 0.56
//         },
//         A: {
//             N: 0,
//             L: 0.22,
//             H: 0.56
//         }
//         // C, I and A have the same weights

//     };

//     var p;
//     var val = {},
//         metricWeight = {};
//     try {
//         for (p in this.bg) {
//             val[p] = this.valueofradio(this.calc.elements[p]);
//             if (typeof val[p] === "undefined" || val[p] === null) {
//                 return "?";
//             }
//             metricWeight[p] = Weight[p][val[p]];
//         }
//     } catch (err) {
//         return err; // TODO: need to catch and return sensible error value & do a better job of specifying *which* parm is at fault.
//     }
//     metricWeight.PR = Weight.PR[val.S][val.PR];
//     //
//     // CALCULATE THE CVSS BASE SCORE
//     //
//     var roundUp1 = function Roundup(input) {
//         var int_input = Math.round(input * 100000);
//         if (int_input % 10000 === 0) {
//             return int_input / 100000
//         } else {
//             return (Math.floor(int_input / 10000) + 1) / 10
//         }
//     };
//     try {
//         var baseScore, impactSubScore, impact, exploitability;
//         var impactSubScoreMultiplier = (1 - ((1 - metricWeight.C) * (1 - metricWeight.I) * (1 - metricWeight.A)));
//         if (val.S === 'U') {
//             impactSubScore = metricWeight.S * impactSubScoreMultiplier;
//         } else {
//             impactSubScore = metricWeight.S * (impactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(impactSubScoreMultiplier - 0.02, 15);
//         }
//         var exploitabalitySubScore = exploitabilityCoefficient * metricWeight.AV * metricWeight.AC * metricWeight.PR * metricWeight.UI;
//         if (impactSubScore <= 0) {
//             baseScore = 0;
//         } else {
//             if (val.S === 'U') {
//                 baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore), 10));
//             } else {
//                 baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore) * scopeCoefficient, 10));
//             }
//         }

//         return baseScore.toFixed(1);
//     } catch (err) {
//         return err;
//     }
// };

// CVSS.prototype.get = function() {
//     return {
//         score: this.score.innerHTML,
//         vector: this.vector.innerHTML
//     };
// };

// CVSS.prototype.setMetric = function(a) {
//     var vectorString = this.vector.innerHTML;
//     if (/AV:.\/AC:.\/PR:.\/UI:.\/S:.\/C:.\/I:.\/A:./.test(vectorString)) {} else {
//         vectorString = 'AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_';
//     }
//     //e("E" + a.id).checked = true;
//     var newVec = vectorString.replace(new RegExp('\\b' + a.name + ':.'), a.name + ':' + a.value);
//     this.set(newVec);
// };

// CVSS.prototype.set = function(vec) {
//     var newVec = 'CVSS:3.1/';
//     var sep = '';
//     for (var m in this.bm) {
//         var match = (new RegExp('\\b(' + m + ':[' + this.bmgReg[m] + '])')).exec(vec);
//         if (match !== null) {
//             var check = match[0].replace(':', '');
//             this.bme[check].checked = true;
//             newVec = newVec + sep + match[0];
//         } else if ((m in { C: '', I: '', A: '' }) && (match = (new RegExp('\\b(' + m + ':C)')).exec(vec)) !== null) {
//             // compatibility with v2 only for CIA:C
//             this.bme[m + 'H'].checked = true;
//             newVec = newVec + sep + m + ':H';
//         } else {
//             newVec = newVec + sep + m + ':_';
//             for (var j in this.bm[m]) {
//                 this.bme[m + j].checked = false;
//             }
//         }
//         sep = '/';
//     }
//     this.update(newVec);
// };

// CVSS.prototype.update = function(newVec) {
//     this.vector.innerHTML = newVec;
//     var s = this.calculate();
//     this.score.innerHTML = s;
//     var rating = this.severityRating(s);
//     this.severity.className = rating.name + ' severity';
//     this.severity.innerHTML = rating.name + '<sub>' + rating.bottom + ' - ' + rating.top + '</sub>';
//     this.severity.title = rating.bottom + ' - ' + rating.top;
//     if (this.options !== undefined && this.options.onchange !== undefined) {
//         this.options.onchange();
//     }
// };
