// ============================================================
//  NoCard.m — 「无卡密版」注入 dylib
//
//  原理：用 Objective-C 运行时动态查找并替换卡密相关方法，
//        完全不依赖任何硬编码地址（避开 chained fixups 难题）。
//
//  注入方式：在 Core 的 Mach-O 头部插入 LC_LOAD_DYLIB 指向本 dylib。
//
//  hook 策略（多重保险）：
//    1. hasLocalActivationCard          -> 永远返回 YES
//    2. 所有名字含 activat/card/auth 的方法 -> 包装成成功回调
//    3. 兜底：把所有返回 BOOL 的 "has*/is*" 方法强制返回 YES
// ============================================================

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <string.h>
#import <stdlib.h>

// ---------- 日志（用函数而非宏，避免 __VA_ARGS__ 兼容问题）----------
static void NCLog(NSString *msg) {
    NSLog(@"[NoCard] %@", msg);
}
#define NCLOG(fmt, ...) NCLog([NSString stringWithFormat:(fmt), ##__VA_ARGS__])

// ============================================================
//  第 1 层：直接替换 hasLocalActivationCard
// ============================================================
static BOOL nc_hasLocalActivationCard(id self, SEL _cmd) {
    NCLOG(@"hasLocalActivationCard -> YES (强制)");
    return YES;
}

// ============================================================
//  第 2 层：替换激活相关方法（带 completion 的）
// ============================================================
// createOrRefreshSessionWithCard:completion:
// ARC 下 id -> block 需经 void* 中转，否则报"ownership qualifier has no effect"
static void nc_createOrRefresh(id self, SEL _cmd, id card, id completion) {
    NCLOG(@"createOrRefreshSessionWithCard -> 伪造成功");
    if (!completion) return;
    typedef void (^NCCompletion1)(id, id);
    void *p = (__bridge void *)completion;
    NCCompletion1 blk = (__bridge NCCompletion1)p;
    @try {
        blk(@"NOCARD_TOKEN", nil);
    } @catch (NSException *e) {
        NCLOG(@"回调异常: %@", e);
    }
}

// finishActivationWithCard:pending:progress:completion:
static void nc_finishActivation(id self, SEL _cmd, id card, id pending, id progress, id completion) {
    NCLOG(@"finishActivationWithCard -> 强制成功");
    if (!completion) return;
    typedef void (^NCCompletion2)(BOOL, id);
    void *p = (__bridge void *)completion;
    NCCompletion2 blk = (__bridge NCCompletion2)p;
    @try {
        blk(YES, nil);
    } @catch (NSException *e) {
        NCLOG(@"回调异常: %@", e);
    }
}

// ============================================================
//  通用：把任意方法替换成"返回 YES"
// ============================================================
static BOOL nc_returnYES(id self, SEL _cmd) {
    NCLOG(@"%@ -> YES (通用兜底)", NSStringFromSelector(_cmd));
    return YES;
}

// 通用：无参返回 nil（安全空实现，备用）
__attribute__((unused))
static id nc_returnNil(id self, SEL _cmd) {
    return nil;
}

// ============================================================
//  自动扫描并 hook
// ============================================================
static void nc_hookClass(const char *className,
                         const char *selName,
                         IMP newImp) {
    Class cls = objc_getClass(className);
    if (!cls) return;
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        // 也试类方法
        m = class_getClassMethod(cls, sel);
    }
    if (!m) return;
    method_setImplementation(m, newImp);
    NCLOG(@"已 hook: %s %s", className, selName);
}

// 遍历所有类，找出"像卡密检查"的方法
static int nc_scanAndHook(void) {
    int hooked = 0;
    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);

    for (unsigned int i = 0; i < classCount; i++) {
        Class cls = classes[i];
        const char *cn = class_getName(cls);
        if (!cn) continue;

        // 只处理 PPMT 相关类
        if (strncmp(cn, "PPMT", 4) != 0) continue;

        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);

        for (unsigned int j = 0; j < methodCount; j++) {
            SEL sel = method_getName(methods[j]);
            const char *sn = sel_getName(sel);
            if (!sn) continue;

            // 只处理无参方法（不含冒号）
            if (strchr(sn, ':') != NULL) continue;

            // 匹配"卡密/激活"相关的名字
            BOOL nameHit =
                (strstr(sn, "hasLocalActivation") != NULL) ||
                (strstr(sn, "hasCard") != NULL) ||
                (strstr(sn, "isActivated") != NULL) ||
                (strstr(sn, "hasActivation") != NULL) ||
                (strstr(sn, "cardRequired") != NULL);

            if (nameHit) {
                method_setImplementation(methods[j], (IMP)nc_returnYES);
                NCLog([NSString stringWithFormat:@"扫描 hook: %s [%s]", cn, sn]);
                hooked++;
            }
        }
        if (methods) free(methods);
    }
    if (classes) free(classes);
    return hooked;
}

// ============================================================
//  入口：dylib 加载时执行
// ============================================================
__attribute__((constructor))
static void NoCardInit(void) {
    NCLOG(@"========================================");
    NCLOG(@" NoCard 无卡密注入已加载");
    NCLOG(@"========================================");

    // 1. 精确 hook 已知方法（多个类都试）
    const char *classNames[] = {
        "PPMTActivationService",
        "PPMTRewardsAPI",
        "PPMTActivationViewController",
        "PPMTRewardsCenter",
        NULL
    };

    for (int i = 0; classNames[i]; i++) {
        nc_hookClass(classNames[i], "hasLocalActivationCard", (IMP)nc_hasLocalActivationCard);
        nc_hookClass(classNames[i],
                     "createOrRefreshSessionWithCard:completion:", (IMP)nc_createOrRefresh);
        nc_hookClass(classNames[i],
                     "finishActivationWithCard:pending:progress:completion:", (IMP)nc_finishActivation);
    }

    // 2. 扫描兜底
    int n = nc_scanAndHook();
    NCLOG(@"扫描完成，额外 hook 了 %d 个方法", n);

    NCLOG(@"NoCard 初始化完成 ✅");
}
