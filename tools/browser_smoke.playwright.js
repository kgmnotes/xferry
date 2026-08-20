async (page) => {
  const baseUrl = __XFERRY_BASE_URL__;
  const unavailableUrl = __XFERRY_UNAVAILABLE_URL__;
  const externalTarget = __XFERRY_EXTERNAL_TARGET__;
  const smokeMode = __XFERRY_SMOKE_MODE__;
  const artifactDir = __XFERRY_ARTIFACT_DIR__;
  const uploadFilePath = __XFERRY_UPLOAD_FILE__;
  const unicodeUploadFilePath = __XFERRY_UNICODE_UPLOAD_FILE__;
  const opsecUploadUrlBoundaryFilePath = __XFERRY_OPSEC_UPLOAD_URL_BOUNDARY_FILE__;
  const opsecUploadFilePath = __XFERRY_OPSEC_UPLOAD_FILE__;
  const opsecUploadBoundaryFilePath = __XFERRY_OPSEC_UPLOAD_BOUNDARY_FILE__;
  const opsecUploadLargeFilePath = __XFERRY_OPSEC_UPLOAD_LARGE_FILE__;
  const browserIssues = [];
  const rootUrl = String(baseUrl || "").replace(/#.*$/, "");
  const topTabContract = [
    { id: "tab-upload", target: "upload", key: "tabUpload" },
    { id: "tab-files", target: "files", key: "tabFiles" },
    { id: "tab-request", target: "request", key: "tabRequests" },
    { id: "tab-opsec", target: "opsec", key: "tabOpsec" },
    { id: "tab-notepad", target: "notepad", key: "tabNotepad" },
  ];
  const topTabLabels = {
    ru: ["Отправить", "Файлы", "Запросы", "Расширенные", "Блокнот"],
    en: ["Send", "Files", "Requests", "Advanced", "Notepad"],
  };

  function requestPathname(request) {
    const withoutOrigin = String(request.url()).replace(
      /^[a-z][a-z0-9+.-]*:\/\/[^/]+/i,
      ""
    );
    return withoutOrigin.split(/[?#]/, 1)[0] || "/";
  }

  function fixtureName(filePath) {
    return String(filePath || "").split(/[\\/]/).pop() || "";
  }

  function recordBrowserIssue(kind, message, location = {}) {
    browserIssues.push({
      kind,
      message: String(message || ""),
      url: location.url || "",
      lineNumber: location.lineNumber || 0,
      columnNumber: location.columnNumber || 0,
    });
  }

  page.on("pageerror", (error) => {
    recordBrowserIssue("pageerror", error.message, { url: page.url() });
  });

  page.on("console", (message) => {
    if (message.type() !== "error") {
      return;
    }
    recordBrowserIssue("console", message.text(), message.location());
  });

  function isExpectedConsoleIssue(issue) {
    if (
      issue.kind !== "console" ||
      !issue.message.includes("Failed to load resource: the server responded with a status of 404 (Not Found)")
    ) {
      return false;
    }

    const issueUrl = String(issue.url || "");
    return issueUrl.includes("/missing-browser-smoke.txt");
  }

  function isExpectedUnavailableNotepadIssue(issue, expectedUrl) {
    return Boolean(
      expectedUrl &&
      issue.kind === "console" &&
      issue.message ===
        "Failed to load resource: the server responded with a status of 501 (Not Implemented)" &&
      String(issue.url || "") === expectedUrl
    );
  }

  function getUnexpectedBrowserIssues(issues, options = {}) {
    const since = Number.isInteger(options.since) && options.since >= 0 ? options.since : 0;
    const scopedIssues = issues.slice(since);
    const expectedUnavailableNotepadUrl =
      typeof options.expectedUnavailableNotepadUrl === "string"
        ? options.expectedUnavailableNotepadUrl
        : "";
    const expectedUnavailableIssues = expectedUnavailableNotepadUrl
      ? scopedIssues.filter((issue) =>
          isExpectedUnavailableNotepadIssue(issue, expectedUnavailableNotepadUrl)
        )
      : [];
    const acceptedUnavailableIssue =
      expectedUnavailableIssues.length === 1 ? expectedUnavailableIssues[0] : null;

    return scopedIssues.filter(
      (issue) =>
        !isExpectedConsoleIssue(issue) &&
        (!acceptedUnavailableIssue || issue !== acceptedUnavailableIssue)
    );
  }

  async function assertNoBrowserIssues(label, options = {}) {
    await page.waitForTimeout(100);
    const unexpectedIssues = getUnexpectedBrowserIssues(browserIssues, options);
    if (unexpectedIssues.length === 0) {
      return;
    }
    throw new Error(`${label} browser issues: ${JSON.stringify(unexpectedIssues.slice(0, 10))}`);
  }

  async function waitForSpaReady() {
    await page.waitForLoadState("domcontentloaded");
    await page.locator("#tab-upload").waitFor({ state: "visible" });
    await page.locator('[role="tabpanel"]:not([hidden])').first().waitFor({ state: "visible" });
    await page.locator("#pathInput").waitFor({ state: "attached" });
    await page.locator("#uploadBtn").waitFor({ state: "attached" });
  }

  async function installClipboardMock() {
    const installMock = () => {
      window.__xferryBrowserClipboardText = String(window.__xferryBrowserClipboardText || "");
      if (window.__xferryClipboardMockInstalled) {
        return;
      }

      const clipboard = {
        writeText: async (text) => {
          window.__xferryBrowserClipboardText = String(text ?? "");
        },
        readText: async () => String(window.__xferryBrowserClipboardText || ""),
      };

      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        get: () => clipboard,
      });

      window.__xferryClipboardMockInstalled = true;
    };

    await page.addInitScript(installMock);
    await page.evaluate(installMock);
  }

  async function waitForPageCondition(label, pageFunction, arg = null, timeout = 10000) {
    try {
      await page.waitForFunction(pageFunction, arg, { timeout });
    } catch (error) {
      throw new Error(`${label}: ${error.message}`);
    }
  }

  async function waitForPopupCondition(label, targetPage, pageFunction, arg = null, timeout = 10000) {
    try {
      await targetPage.waitForFunction(pageFunction, arg, { timeout });
    } catch (error) {
      throw new Error(`${label}: ${error.message}`);
    }
  }

  async function waitForText(locator, textOrPattern, timeout = 10000) {
    await locator.waitFor({ state: "attached", timeout });
    const selector = await locator.evaluate((node) => {
      if (!node.id) {
        throw new Error("waitForText requires a locator with an id-backed element");
      }
      return `#${node.id}`;
    });
    const isRegex = textOrPattern instanceof RegExp;
    const expected = isRegex ? textOrPattern.source : textOrPattern;
    const flags = isRegex ? textOrPattern.flags : "";
    await waitForPageCondition(
      `waitForText(${selector})`,
      ([targetSelector, targetText, targetFlags, targetIsRegex]) => {
        const matcher = targetIsRegex ? new RegExp(targetText, targetFlags) : null;
        const element = document.querySelector(targetSelector);
        if (!element) {
          return false;
        }
        const trace = element.closest("details.tool-trace");
        if (trace && !trace.open) {
          trace.open = true;
        }
        const content = element.innerText;
        return matcher ? matcher.test(content) : content.includes(targetText);
      },
      [selector, expected, flags, isRegex],
      timeout
    );
  }

  async function expandTraceForSelector(selector) {
    await page.evaluate((targetSelector) => {
      const element = document.querySelector(targetSelector);
      const trace = element?.closest("details.tool-trace");
      if (trace && !trace.open) {
        trace.open = true;
      }
    }, selector);
  }

  async function waitForLiveRegionText(regionId, textOrPattern, timeout = 10000) {
    const isRegex = textOrPattern instanceof RegExp;
    const expected = isRegex ? textOrPattern.source : textOrPattern;
    const flags = isRegex ? textOrPattern.flags : "";
    await waitForPageCondition(
      `waitForLiveRegionText(${regionId})`,
      ([targetRegionId, targetText, targetFlags, targetIsRegex]) => {
        const region = document.getElementById(targetRegionId);
        if (!region) {
          return false;
        }
        const content = region.innerText || region.textContent || "";
        if (targetIsRegex) {
          return new RegExp(targetText, targetFlags).test(content);
        }
        return content.includes(targetText);
      },
      [regionId, expected, flags, isRegex],
      timeout
    );
  }

  async function assertVisibleUploadMethodComposer(label) {
    const composer = await page.evaluate(() => {
      const group = document.querySelector("#upload-tab .upload-method-group");
      const methods = Array.from(document.querySelectorAll(".upload-method-btn[data-upload-method]"));
      const groupRect = group?.getBoundingClientRect();
      return {
        groupExists: Boolean(group),
        methods: methods.map((button) => {
          const rect = button.getBoundingClientRect();
          return {
            method: button.dataset.uploadMethod,
            visible: button.getClientRects().length > 0,
            inGroup: Boolean(group?.contains(button)),
            left: Math.round(rect.left),
            right: Math.round(rect.right),
            top: Math.round(rect.top),
            height: Math.round(rect.height),
            groupLeft: Math.round(groupRect?.left || 0),
            groupRight: Math.round(groupRect?.right || 0),
          };
        }),
      };
    });
    const expectedMethods = ["POST", "NONE", "PUT", "PATCH"];
    const allOnOneRow = composer.methods.every((item) => item.top === composer.methods[0]?.top);
    const valid = composer.groupExists &&
      composer.methods.length === expectedMethods.length &&
      composer.methods.map((item) => item.method).join(",") === expectedMethods.join(",") &&
      composer.methods.every((item) => (
        item.visible &&
        item.inGroup &&
        item.height >= 44 &&
        item.left >= item.groupLeft &&
        item.right <= item.groupRight
      )) &&
      allOnOneRow;
    if (!valid) {
      throw new Error(`${label}: upload method composer contract failed: ${JSON.stringify(composer)}`);
    }
  }

  async function waitForValue(selector, expected, timeout = 10000) {
    await waitForPageCondition(
      `waitForValue(${selector})`,
      ([targetSelector, targetValue]) => {
        const element = document.querySelector(targetSelector);
        return Boolean(element && "value" in element && element.value === targetValue);
      },
      [selector, expected],
      timeout
    );
  }

  async function confirmAppDialog(expectedTextOrPattern, timeout = 10000) {
    const dialog = page.locator('#appDialog [role="alertdialog"]');
    try {
      await dialog.waitFor({ state: "visible", timeout });
    } catch (error) {
      const snapshot = await page.evaluate(() => {
        const activeTab = document.querySelector('.tab[role="tab"].active[data-tab-target]');
        const activeElement = document.activeElement;
        return {
          activeTabId: activeTab?.id || "",
          activeTabText: activeTab?.textContent?.trim() || "",
          activeElementId: activeElement?.id || "",
          activeElementText: activeElement?.textContent?.trim() || "",
          appDialogText: document.getElementById("appDialog")?.textContent?.trim() || "",
        };
      });
      const expectedDialog = String(expectedTextOrPattern);
      throw new Error(
        `confirmAppDialog(${expectedDialog}) did not open: ` +
          `${JSON.stringify(snapshot)}; ${error.message}`
      );
    }
    if (expectedTextOrPattern) {
      const isRegex = expectedTextOrPattern instanceof RegExp;
      const expected = isRegex ? expectedTextOrPattern.source : expectedTextOrPattern;
      const flags = isRegex ? expectedTextOrPattern.flags : "";
      await waitForPageCondition(
        "confirmAppDialog text",
        ([targetText, targetFlags, targetIsRegex]) => {
          const root = document.getElementById("appDialog");
          if (!root) {
            return false;
          }
          const content = root.innerText;
          if (targetIsRegex) {
            return new RegExp(targetText, targetFlags).test(content);
          }
          return content.includes(targetText);
        },
        [expected, flags, isRegex],
        timeout
      );
    }
    await dialog.locator('[data-dialog-action="confirm"]').click();
    await dialog.waitFor({ state: "detached", timeout });
  }

  async function assertSharedDialogRoleContract(timeout = 10000) {
    await page.locator("#themeBtn").focus();

    await page.evaluate(() => {
      void window.XferryApp.service("dialogs").notice({
        title: "Browser Smoke Notice",
        message: "Notice dialog role contract",
        details: "Dialog detail geometry contract",
        confirmLabel: "Acknowledge",
        triggerEl: document.getElementById("themeBtn"),
      });
    });

    await waitForPageCondition(
      "notice dialog role contract",
      () => {
        const dialog = document.querySelector('#appDialog [role="dialog"]');
        const alertDialog = document.querySelector('#appDialog [role="alertdialog"]');
        const confirm = document.querySelector('#appDialog [data-dialog-action="confirm"]');
        return Boolean(
          dialog &&
          !alertDialog &&
          dialog.getAttribute("aria-modal") === "true" &&
          document.activeElement === confirm
        );
      },
      null,
      timeout
    );

    const noticeGeometry = await page.evaluate(() => {
      const dialog = document.querySelector('#appDialog [role="dialog"]');
      const details = document.querySelector("#appDialog .app-dialog__details");
      const confirm = document.querySelector('#appDialog [data-dialog-action="confirm"]');
      if (!dialog || !details || !confirm) {
        throw new Error("Notice dialog geometry targets are missing");
      }
      const confirmRect = confirm.getBoundingClientRect();
      return {
        dialogRadius: getComputedStyle(dialog).borderRadius,
        detailsRadius: getComputedStyle(details).borderRadius,
        confirmWidth: confirmRect.width,
        confirmHeight: confirmRect.height,
      };
    });
    if (
      noticeGeometry.dialogRadius !== "0px" ||
      noticeGeometry.detailsRadius !== "0px" ||
      noticeGeometry.confirmWidth < 44 ||
      noticeGeometry.confirmHeight < 44
    ) {
      throw new Error(`Shared dialog design-system geometry failed: ${JSON.stringify(noticeGeometry)}`);
    }

    await page.keyboard.press("Escape");
    await page.locator("#appDialog").waitFor({ state: "detached", timeout });
    await waitForPageCondition(
      "notice dialog focus restored",
      () => document.activeElement?.id === "themeBtn",
      null,
      timeout
    );

    await page.evaluate(() => {
      void window.XferryApp.service("dialogs").confirm({
        title: "Browser Smoke Confirm",
        message: "Confirm dialog role contract",
        confirmLabel: "Delete",
        cancelLabel: "Cancel",
        triggerEl: document.getElementById("themeBtn"),
      });
    });

    await waitForPageCondition(
      "confirm dialog role contract",
      () => {
        const dialog = document.querySelector('#appDialog [role="alertdialog"]');
        const plainDialog = document.querySelector('#appDialog [role="dialog"]');
        const cancel = document.querySelector('#appDialog [data-dialog-action="cancel"]');
        return Boolean(
          dialog &&
          !plainDialog &&
          dialog.getAttribute("aria-modal") === "true" &&
          document.activeElement === cancel
        );
      },
      null,
      timeout
    );

    await page.keyboard.press("Escape");
    await page.locator("#appDialog").waitFor({ state: "detached", timeout });
    await waitForPageCondition(
      "confirm dialog focus restored",
      () => document.activeElement?.id === "themeBtn",
      null,
      timeout
    );
  }

  async function waitForConnectionStatus(expectedState, expectedTransport, timeout = 10000) {
    await waitForPageCondition(
      `waitForConnectionStatus(${expectedState},${expectedTransport})`,
      ([state, transport]) => {
        const element = document.getElementById("notepadConnStatus");
        const text = document.getElementById("notepadConnStatusText");
        return Boolean(
          element &&
          text &&
          element.dataset &&
          element.dataset.state === state &&
          element.dataset.transport === transport &&
          text.textContent.trim().length > 0 &&
          element.getAttribute("aria-label") === text.textContent.trim()
        );
      },
      [expectedState, expectedTransport],
      timeout
    );
  }

  async function switchLanguage(lang, timeout = 10000) {
    const selector = lang === "en" ? "#langEn" : "#langRu";
    const otherSelector = lang === "en" ? "#langRu" : "#langEn";
    await page.locator(selector).click();
    await waitForPageCondition(
      `switchLanguage(${lang})`,
      ([targetLang, targetSelector, targetOtherSelector]) => {
        const button = document.querySelector(targetSelector);
        const otherButton = document.querySelector(targetOtherSelector);
        return Boolean(
          document.documentElement.lang === targetLang &&
          button &&
          button.classList.contains("active") &&
          button.getAttribute("aria-pressed") === "true" &&
          otherButton &&
          otherButton.getAttribute("aria-pressed") === "false"
        );
      },
      [lang, selector, otherSelector],
      timeout
    );
  }

  async function assertUnsupportedStoredLanguageFallsBack() {
    await page.evaluate(() => {
      localStorage.setItem("lang", "unsupported-browser-smoke-locale");
    });
    await page.reload({ waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForPageCondition(
      "unsupported stored language falls back to Russian",
      () => {
        const ruButton = document.getElementById("langRu");
        const enButton = document.getElementById("langEn");
        return Boolean(
          document.documentElement.lang === "ru" &&
          localStorage.getItem("lang") === "ru" &&
          ruButton?.classList.contains("active") &&
          ruButton?.getAttribute("aria-pressed") === "true" &&
          enButton?.getAttribute("aria-pressed") === "false" &&
          document.getElementById("tab-upload")?.textContent?.trim() === "Отправить"
        );
      },
      null,
      10000
    );
  }

  function colorsNearlyMatch(left, right) {
    return Boolean(
      left &&
      right &&
      Math.abs(left.red - right.red) <= 1 &&
      Math.abs(left.green - right.green) <= 1 &&
      Math.abs(left.blue - right.blue) <= 1 &&
      Math.abs(left.alpha - right.alpha) <= 0.01
    );
  }

  async function inspectElementContrast(locator, metadata = {}) {
    if (await locator.count() === 0) {
      throw new Error(`Missing contrast target: ${metadata.selector || "<locator>"}`);
    }
    return locator.first().evaluate((element, inspectMetadata) => {
      const parseColor = (value) => {
        const text = String(value || "").trim();
        const canvas = document.createElement("canvas");
        canvas.width = 1;
        canvas.height = 1;
        const context = canvas.getContext("2d", { willReadFrequently: true });
        if (!context) {
          throw new Error("Canvas 2D context is unavailable for contrast checks");
        }
        context.clearRect(0, 0, 1, 1);
        context.fillStyle = text;
        context.fillRect(0, 0, 1, 1);
        const [red, green, blue, alpha] = context.getImageData(0, 0, 1, 1).data;
        return { red, green, blue, alpha: alpha / 255 };
      };
      const channelLuminance = (channel) => {
        const normalized = channel / 255;
        return normalized <= 0.04045
          ? normalized / 12.92
          : ((normalized + 0.055) / 1.055) ** 2.4;
      };
      const luminance = (color) => (
        0.2126 * channelLuminance(color.red) +
        0.7152 * channelLuminance(color.green) +
        0.0722 * channelLuminance(color.blue)
      );
      const contrastRatio = (foreground, background) => {
        const lighter = Math.max(luminance(foreground), luminance(background));
        const darker = Math.min(luminance(foreground), luminance(background));
        return (lighter + 0.05) / (darker + 0.05);
      };
      const style = getComputedStyle(element);
      const rootStyle = getComputedStyle(document.documentElement);
      const foreground = parseColor(style.color);
      const background = parseColor(style.backgroundColor);
      const accentValue = style.getPropertyValue("--upload-method-accent").trim();
      return {
        ...inspectMetadata,
        foreground: style.color,
        background: style.backgroundColor,
        border: style.borderTopColor,
        ratio: contrastRatio(foreground, background),
        opaque: foreground.alpha === 1 && background.alpha === 1,
        colorSamples: {
          foreground,
          background,
          border: parseColor(style.borderTopColor),
          elevated: parseColor(rootStyle.getPropertyValue("--bg-elevated")),
          uploadMethodAccent: accentValue ? parseColor(accentValue) : null,
        },
        borderWidths: [
          style.borderTopWidth,
          style.borderRightWidth,
          style.borderBottomWidth,
          style.borderLeftWidth,
        ],
        fontWeight: Number.parseInt(style.fontWeight, 10),
      };
    }, metadata);
  }

  async function assertLightThemeContrast() {
    const selectors = [
      [".request-method-switch .btn-get", "primary"],
      [".request-method-switch .btn-put", "secondary"],
      [".request-method-switch .btn-post", "tertiary"],
      [".request-method-switch .btn-none", "orange"],
      [".request-method-switch .btn-ping", "danger"],
      [".request-method-switch .btn-patch", "opsec"],
      [".request-method-switch .btn-note", "note"],
      ["#langRu", "active language"],
    ];
    const inspections = [];
    for (const [selector, label] of selectors) {
      inspections.push(await inspectElementContrast(
        page.locator(selector),
        { selector, label }
      ));
    }

    const nonOpaque = inspections.find((item) => !item.opaque);
    if (nonOpaque) {
      throw new Error(`Contrast target is not opaque: ${nonOpaque.selector}`);
    }
    const contrastChecks = inspections.map((item) => ({
      selector: item.selector,
      label: item.label,
      foreground: item.foreground,
      background: item.background,
      ratio: item.ratio,
    }));
    const failures = contrastChecks.filter((item) => item.ratio < 4.5);
    if (failures.length > 0) {
      throw new Error(`Light-theme contrast below 4.5:1: ${JSON.stringify(failures)}`);
    }
    return contrastChecks;
  }

  async function assertHeaderStateControls() {
    await switchLanguage("ru");
    if (await page.locator("#themeBtn").getAttribute("aria-pressed") === "true") {
      await page.locator("#themeBtn").click();
    }
    await waitForPageCondition(
      "Russian language and dark theme expose state",
      () => {
        const ru = document.getElementById("langRu");
        const en = document.getElementById("langEn");
        const theme = document.getElementById("themeBtn");
        const mark = document.getElementById("brandMark");
        const favicon = document.getElementById("appFavicon");
        return Boolean(
          ru?.getAttribute("aria-pressed") === "true" &&
          ru?.getAttribute("aria-label") === "Русский язык выбран" &&
          en?.getAttribute("aria-pressed") === "false" &&
          en?.getAttribute("aria-label") === "Переключить на английский язык" &&
          theme?.getAttribute("aria-pressed") === "false" &&
          theme?.getAttribute("aria-label") === "Тёмная тема включена. Переключить на светлую" &&
          new URL(mark?.src || "", window.location.href).pathname === "/static/ui/xferry-mark.svg" &&
          new URL(favicon?.href || "", window.location.href).pathname === "/static/ui/xferry-mark.svg"
        );
      }
    );

    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.locator("#themeBtn").click();
    await waitForPageCondition(
      "light theme exposes pressed state",
      () => {
        const theme = document.getElementById("themeBtn");
        const mark = document.getElementById("brandMark");
        const favicon = document.getElementById("appFavicon");
        return Boolean(
          document.documentElement.getAttribute("data-theme") === "light" &&
          theme?.getAttribute("aria-pressed") === "true" &&
          theme?.getAttribute("aria-label") === "Светлая тема включена. Переключить на тёмную" &&
          new URL(mark?.src || "", window.location.href).pathname === "/static/ui/xferry-mark-light.svg" &&
          new URL(favicon?.href || "", window.location.href).pathname === "/static/ui/xferry-mark-light.svg"
        );
      }
    );
    const contrastChecks = await assertLightThemeContrast();

    await page.locator("#themeBtn").click();
    await page.emulateMedia({ reducedMotion: "no-preference" });
    await switchLanguage("en");
    await waitForPageCondition(
      "English language and dark theme expose state",
      () => {
        const ru = document.getElementById("langRu");
        const en = document.getElementById("langEn");
        const theme = document.getElementById("themeBtn");
        const mark = document.getElementById("brandMark");
        const favicon = document.getElementById("appFavicon");
        return Boolean(
          ru?.getAttribute("aria-pressed") === "false" &&
          ru?.getAttribute("aria-label") === "Switch to Russian" &&
          en?.getAttribute("aria-pressed") === "true" &&
          en?.getAttribute("aria-label") === "English language selected" &&
          theme?.getAttribute("aria-pressed") === "false" &&
          theme?.getAttribute("aria-label") === "Dark theme is active. Switch to light theme" &&
          new URL(mark?.src || "", window.location.href).pathname === "/static/ui/xferry-mark.svg" &&
          new URL(favicon?.href || "", window.location.href).pathname === "/static/ui/xferry-mark.svg"
        );
      }
    );
    await switchLanguage("ru");
    return contrastChecks;
  }

  async function assertSharedVisualSystem() {
    async function inspectTheme(theme, expected) {
      await page.evaluate((targetTheme) => {
        document.documentElement.setAttribute("data-theme", targetTheme);
      }, theme);
      await waitForPageCondition(
        `shared visual system ${theme}`,
        ([targetTheme, expectedCanvas]) => {
          const root = document.documentElement;
          const rootStyle = getComputedStyle(root);
          return (
            root.getAttribute("data-theme") === targetTheme &&
            rootStyle.getPropertyValue("--bg-canvas").trim() === expectedCanvas
          );
        },
        [theme, expected.canvas]
      );

      return page.evaluate(({ canvas, surface, elevated, ink }) => {
        const rootStyle = getComputedStyle(document.documentElement);
        const styleOf = (selector, pseudo = null) => {
          const element = document.querySelector(selector);
          if (!element) {
            throw new Error(`Missing shared visual-system target: ${selector}`);
          }
          const style = getComputedStyle(element, pseudo);
          return {
            selector,
            backgroundColor: style.backgroundColor,
            backgroundImage: style.backgroundImage,
            borderRadius: style.borderRadius,
            borderTopWidth: style.borderTopWidth,
            borderRightWidth: style.borderRightWidth,
            borderBottomWidth: style.borderBottomWidth,
            borderLeftWidth: style.borderLeftWidth,
            boxShadow: style.boxShadow,
            backdropFilter: style.backdropFilter || "",
            webkitBackdropFilter: style.webkitBackdropFilter || "",
            fontFamily: style.fontFamily,
          };
        };
        const structural = [
          "body",
          ".panel",
          ".tool-card",
          ".mode-tabs",
          ".response-area",
          ".tool-result",
        ].map((selector) => styleOf(selector));
        const interactive = ["#themeBtn", "#pathInput", "#dropZone"].map((selector) => styleOf(selector));
        const activeTab = styleOf(".mode-tabs .tab.active");
        const progressProbe = document.createElement("div");
        progressProbe.className = "progress-container";
        progressProbe.hidden = true;
        document.body.append(progressProbe);
        const progressStyle = getComputedStyle(progressProbe);
        const progress = {
          selector: ".progress-container",
          borderRadius: progressStyle.borderRadius,
        };
        progressProbe.remove();
        return {
          expected: { canvas, surface, elevated, ink },
          tokens: {
            canvas: rootStyle.getPropertyValue("--bg-canvas").trim(),
            surface: rootStyle.getPropertyValue("--bg-muted").trim(),
            elevated: rootStyle.getPropertyValue("--bg-elevated").trim(),
            ink: rootStyle.getPropertyValue("--text-primary").trim(),
          },
          structural,
          interactive,
          activeTab,
          progress,
        };
      }, expected);
    }

    const dark = await inspectTheme("dark", {
      canvas: "#111315",
      surface: "#1a1d20",
      elevated: "#25292d",
      ink: "#fdfcfc",
    });
    const light = await inspectTheme("light", {
      canvas: "#fdfcfc",
      surface: "#f8f7f7",
      elevated: "#f1eeee",
      ink: "#201d1d",
    });

    for (const snapshot of [dark, light]) {
      if (JSON.stringify(snapshot.tokens) !== JSON.stringify(snapshot.expected)) {
        throw new Error(`Shared visual-system tokens mismatch: ${JSON.stringify(snapshot)}`);
      }
      if (!snapshot.structural.every((item) => (
        item.backgroundImage === "none" &&
        item.borderRadius === "0px" &&
        item.boxShadow === "none" &&
        ["none", ""].includes(item.backdropFilter) &&
        ["none", ""].includes(item.webkitBackdropFilter) &&
        /mono/i.test(item.fontFamily) &&
        !/Inter/i.test(item.fontFamily)
      ))) {
        throw new Error(`Structural visual-system contract failed: ${JSON.stringify(snapshot.structural)}`);
      }
      if (!snapshot.interactive.every((item) => item.borderRadius === "4px")) {
        throw new Error(`Interactive radius contract failed: ${JSON.stringify(snapshot.interactive)}`);
      }
      if (
        snapshot.activeTab.backgroundImage !== "none" ||
        snapshot.activeTab.borderRadius !== "0px" ||
        snapshot.activeTab.borderTopWidth !== "0px" ||
        snapshot.activeTab.borderRightWidth !== "0px" ||
        snapshot.activeTab.borderBottomWidth !== "2px" ||
        snapshot.activeTab.borderLeftWidth !== "0px"
      ) {
        throw new Error(`Flat top-tab contract failed: ${JSON.stringify(snapshot.activeTab)}`);
      }
      if (snapshot.progress.borderRadius !== "999px") {
        throw new Error(`Progress pill contract failed: ${JSON.stringify(snapshot.progress)}`);
      }
    }

    await page.locator("#langEn").focus();
    await page.keyboard.press("Tab");
    await waitForPageCondition(
      "focus ring reaches theme control",
      () => document.activeElement?.id === "themeBtn"
    );
    const focusShadow = await page.locator("#themeBtn").evaluate((element) => getComputedStyle(element).boxShadow);
    if (focusShadow === "none" || !focusShadow.includes("3px")) {
      throw new Error(`Focus ring contract failed: ${focusShadow}`);
    }
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
    return { dark, light, focusShadow };
  }

  async function assertHeaderBrandContract() {
    const states = [
      {
        viewport: "desktop",
        width: 1365,
        height: 768,
        lang: "ru",
        expectedTagline: "Инструмент для тестирования SWG",
        maxTaglineLines: 1,
        minTitleSize: 45,
        maxTitleSize: 50,
      },
      {
        viewport: "mobile",
        width: 390,
        height: 844,
        lang: "en",
        expectedTagline: "SWG testing tool",
        maxTaglineLines: 2,
        minTitleSize: 31,
        maxTitleSize: 34,
      },
    ];
    const snapshots = [];

    for (const state of states) {
      await page.setViewportSize({ width: state.width, height: state.height });
      await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
      await waitForSpaReady();
      await waitForAdvancedUploadReady();
      await switchLanguage(state.lang);
      const snapshot = await page.evaluate(() => {
        const lockup = document.querySelector(".brand-lockup");
        const mark = document.querySelector(".brand-mark");
        const title = document.querySelector(".brand-copy h1");
        const tagline = document.querySelector(".brand-copy p");
        if (!lockup || !mark || !title || !tagline) {
          throw new Error("Missing compact header brand target");
        }
        const lockupRect = lockup.getBoundingClientRect();
        const markRect = mark.getBoundingClientRect();
        const titleRect = title.getBoundingClientRect();
        const taglineRect = tagline.getBoundingClientRect();
        const titleStyle = getComputedStyle(title);
        const taglineStyle = getComputedStyle(tagline);
        const taglineLineHeight = Number.parseFloat(taglineStyle.lineHeight);
        return {
          mascotPresent: Boolean(document.querySelector(".brand-mascot")),
          title: title.textContent.trim(),
          tagline: tagline.textContent.trim(),
          mark: {
            width: Math.round(markRect.width),
            height: Math.round(markRect.height),
            top: Math.round(markRect.top),
          },
          titleTop: Math.round(titleRect.top),
          titleSize: Number.parseFloat(titleStyle.fontSize),
          taglineLines: Math.round(taglineRect.height / taglineLineHeight),
          lockupLeft: Math.round(lockupRect.left),
          lockupRight: Math.round(lockupRect.right),
          taglineRight: Math.round(taglineRect.right),
          viewportWidth: window.innerWidth,
          bodyOverflow: document.documentElement.scrollWidth > window.innerWidth + 2,
        };
      });

      const valid = (
        !snapshot.mascotPresent &&
        snapshot.title === "xferry" &&
        snapshot.tagline === state.expectedTagline &&
        snapshot.mark.width === 40 &&
        snapshot.mark.height === 40 &&
        Math.abs(snapshot.mark.top - snapshot.titleTop) <= 2 &&
        snapshot.titleSize >= state.minTitleSize &&
        snapshot.titleSize <= state.maxTitleSize &&
        snapshot.taglineLines >= 1 &&
        snapshot.taglineLines <= state.maxTaglineLines &&
        snapshot.lockupLeft >= 0 &&
        snapshot.lockupRight <= snapshot.viewportWidth &&
        snapshot.taglineRight <= snapshot.viewportWidth &&
        !snapshot.bodyOverflow
      );
      if (!valid) {
        throw new Error(
          `Compact header brand contract failed ${state.viewport} ${state.lang}: ` +
          JSON.stringify(snapshot)
        );
      }
      snapshots.push({ ...state, ...snapshot });
    }

    await page.setViewportSize({ width: 1440, height: 1024 });
    await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForAdvancedUploadReady();
    await switchLanguage("ru");
    return snapshots;
  }

  async function assertHeaderActionsContract() {
    const snapshot = await page.evaluate(() => {
      const actions = document.querySelector(".topbar__actions");
      const cluster = document.querySelector(".status-cluster");
      return {
        actionsPresent: Boolean(actions),
        actionButtonIds: Array.from(actions?.querySelectorAll("button") || []).map(
          (button) => button.id
        ),
        statusClusterPresent: Boolean(cluster),
        statusChipCount: document.querySelectorAll(".status-chip").length,
        serverAddressPresent: Boolean(document.getElementById("serverAddressValue")),
      };
    });

    const valid = (
      snapshot.actionsPresent &&
      JSON.stringify(snapshot.actionButtonIds) === JSON.stringify(["langRu", "langEn", "themeBtn"]) &&
      !snapshot.statusClusterPresent &&
      snapshot.statusChipCount === 0 &&
      !snapshot.serverAddressPresent
    );
    if (!valid) {
      throw new Error(`Header controls-only contract failed: ${JSON.stringify(snapshot)}`);
    }
    return snapshot;
  }

  async function inspectTargetGeometries(selectors) {
    return page.evaluate((targetSelectors) => targetSelectors.map((selector) => {
      const element = document.querySelector(selector);
      if (!element) {
        return { selector, missing: true, width: 0, height: 0, visible: false };
      }
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return {
        selector,
        missing: false,
        width: rect.width,
        height: rect.height,
        visible: (
          rect.width > 0 &&
          rect.height > 0 &&
          style.display !== "none" &&
          style.visibility !== "hidden"
        ),
      };
    }), selectors);
  }

  async function captureSharedVisualReview() {
    const screenshots = [];
    const audit = {
      uploadMethods: [],
      targets: [],
      structural: [],
    };
    const reviewStates = [
      { viewport: "desktop", width: 1365, height: 768, lang: "ru", theme: "dark" },
      { viewport: "desktop", width: 1365, height: 768, lang: "en", theme: "light" },
      { viewport: "mobile", width: 390, height: 844, lang: "ru", theme: "dark" },
      { viewport: "mobile", width: 390, height: 844, lang: "en", theme: "light" },
    ];
    const targetSelectors = {
      upload: [
        "#dropZone",
        "#uploadBtn",
        "#uploadCompareBtn",
        '#upload-tab [data-upload-method="POST"]',
        '#upload-tab [data-upload-profile="multipart"]',
      ],
      files: ["#browseRootBtn", "#browseUpBtn", "#browsePathInput", "#browseBtn"],
      request: [
        "#pathInput",
        "#requestTechnicalDetails > summary",
        '#request-tab [data-request-method="GET"]',
      ],
      opsec: [
        "#opsecMethodInput",
        "#opsecRandomMethodBtn",
        "#opsecDropZone",
        "#opsecUploadBtn",
        "#opsecSettingsDetails > summary",
      ],
      notepad: [
        "#notepadTitleInput",
        "#notepadNewBtn",
        "#notepadDeleteBtn",
        ".notepad-loss-details__summary",
        "#notepadRefreshBtn",
      ],
    };
    const structuralSelectors = {
      upload: [".upload-request-summary", ".upload-profile-group"],
      files: [".file-browser__toolbar"],
      request: [".request-batch-summary"],
      opsec: [".opsec-outcome-summary__item", ".opsec-settings-group"],
      notepad: [".notepad-loss-details__body"],
    };

    for (const state of reviewStates) {
      await page.setViewportSize({ width: state.width, height: state.height });
      await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
      await waitForSpaReady();
      await waitForAdvancedUploadReady();
      await switchLanguage(state.lang);
      const currentTheme = (await page.locator("html").getAttribute("data-theme")) || "dark";
      if (currentTheme !== state.theme) {
        await page.locator("#themeBtn").click();
      }
      await waitForPageCondition(
        `visual review theme ${state.viewport} ${state.lang} ${state.theme}`,
        (targetTheme) => {
          const activeTheme = document.documentElement.getAttribute("data-theme") || "dark";
          return activeTheme === targetTheme;
        },
        state.theme
      );
      const globalTargets = await inspectTargetGeometries([
        "#langRu",
        "#langEn",
        "#themeBtn",
      ]);
      audit.targets.push(...globalTargets.map((item) => ({
        ...state,
        tab: "global",
        ...item,
      })));

      await page.locator("#tab-upload").click();
      await waitForTabState("upload", { focused: true });
      for (const method of ["POST", "NONE", "PUT", "PATCH"]) {
        const methodButton = page.locator(`#upload-tab [data-upload-method="${method}"]`);
        await methodButton.click();
        await waitForUploadMethodState(method, { focused: true });
        await methodButton.evaluate(async (element) => {
          await Promise.all(element.getAnimations().map((animation) => animation.finished));
        });
        const contrast = await inspectElementContrast(methodButton, {
          ...state,
          method,
        });
        audit.uploadMethods.push({
          ...contrast,
          retainedTint: !colorsNearlyMatch(
            contrast.colorSamples.background,
            contrast.colorSamples.elevated
          ),
          retainedAccentBorder: colorsNearlyMatch(
            contrast.colorSamples.border,
            contrast.colorSamples.uploadMethodAccent
          ),
        });
      }
      await page.locator('#upload-tab [data-upload-method="POST"]').click();
      await waitForUploadMethodState("POST", { focused: true });

      for (const tab of topTabContract) {
        await page.locator(`#${tab.id}`).click();
        await waitForTabState(tab.target, { focused: true });
        const originalDisclosureState = await page.evaluate((target) => {
          const disclosureIds = {
            request: ["requestTechnicalDetails", "requestBatchDetails"],
            opsec: ["opsecSettingsDetails"],
            notepad: ["notepadLossDetails"],
          };
          return (disclosureIds[target] || []).map((id) => {
            const details = document.getElementById(id);
            const open = Boolean(details?.open);
            if (details instanceof HTMLDetailsElement) {
              details.open = true;
            }
            return { id, open };
          });
        }, tab.target);
        const geometry = await page.evaluate(({ target, structural }) => {
          const stage = document.querySelector(".workspace-stage");
          const activePanel = document.getElementById(`${target}-tab`);
          const tabs = Array.from(document.querySelectorAll(".mode-tabs .tab"));
          const panelRect = activePanel?.getBoundingClientRect();
          const stageRect = stage?.getBoundingClientRect();
          const inspectStructural = (selector) => {
            const element = document.querySelector(selector);
            if (!element) {
              return { selector, missing: true, borderRadius: "" };
            }
            return {
              selector,
              missing: false,
              borderRadius: getComputedStyle(element).borderRadius,
            };
          };
          return {
            viewport: { width: window.innerWidth, height: window.innerHeight },
            bodyOverflow: document.documentElement.scrollWidth > window.innerWidth + 2,
            stageTop: Math.round(stageRect?.top || 0),
            activePanel: {
              left: Math.round(panelRect?.left || 0),
              right: Math.round(panelRect?.right || 0),
              width: Math.round(panelRect?.width || 0),
            },
            clippedTabs: tabs.filter((item) => (
              item.scrollWidth > item.clientWidth + 2 ||
              item.scrollHeight > item.clientHeight + 2
            )).map((item) => item.id),
            structural: structural.map(inspectStructural),
          };
        }, {
          target: tab.target,
          structural: structuralSelectors[tab.target] || [],
        });
        const targets = await inspectTargetGeometries(targetSelectors[tab.target] || []);
        await page.evaluate((states) => {
          for (const state of states) {
            const details = document.getElementById(state.id);
            if (details instanceof HTMLDetailsElement) {
              details.open = state.open;
            }
          }
        }, originalDisclosureState);
        audit.targets.push(...targets.map((item) => ({
          ...state,
          tab: tab.target,
          ...item,
        })));
        audit.structural.push(...geometry.structural.map((item) => ({
          ...state,
          tab: tab.target,
          ...item,
        })));
        const validGeometry = (
          !geometry.bodyOverflow &&
          geometry.stageTop <= 390 &&
          geometry.activePanel.width > 0 &&
          geometry.activePanel.left >= -2 &&
          geometry.activePanel.right <= geometry.viewport.width + 2 &&
          geometry.clippedTabs.length === 0
        );
        if (!validGeometry) {
          throw new Error(
            `Visual review geometry failed ${state.viewport} ${state.lang} ` +
            `${state.theme} ${tab.target}: ${JSON.stringify(geometry)}`
          );
        }
        const screenshotPath = (
          `${String(artifactDir).replace(/[\\/]+$/, "")}/` +
          `visual-${state.viewport}-${state.lang}-${state.theme}-${tab.target}.png`
        );
        await page.screenshot({ path: screenshotPath, fullPage: true });
        screenshots.push(screenshotPath);
      }
    }

    await page.setViewportSize({ width: 1440, height: 1024 });
    await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForAdvancedUploadReady();
    const auditFailures = {
      uploadMethods: audit.uploadMethods.filter((item) => (
        !item.opaque ||
        item.ratio < 4.5 ||
        !item.retainedTint ||
        !item.retainedAccentBorder ||
        item.borderWidths.some((width) => width !== "2px") ||
        item.fontWeight < 700
      )),
      targets: audit.targets.filter((item) => (
        item.missing ||
        !item.visible ||
        item.width < 44 ||
        item.height < 44
      )),
      structural: audit.structural.filter((item) => (
        item.missing ||
        item.borderRadius !== "0px"
      )),
    };
    if (Object.values(auditFailures).some((items) => items.length > 0)) {
      throw new Error(`Final design-system audit failed: ${JSON.stringify(auditFailures)}`);
    }
    return screenshots;
  }

  async function assertReducedMotionAndTextlessDisclosures() {
    await page.emulateMedia({ reducedMotion: "reduce" });
    const summaryLocators = await page.locator("details > summary").all();
    const disclosures = [];
    for (let index = 0; index < summaryLocators.length; index += 1) {
      const summary = summaryLocators[index];
      const originalOpen = await summary.evaluate((element) => Boolean(element.parentElement?.open));
      await summary.evaluate((element) => {
        if (element.parentElement instanceof HTMLDetailsElement) {
          element.parentElement.open = false;
        }
      });
      const closed = await summary.evaluate((element) => {
        const before = getComputedStyle(element, "::before");
        const after = getComputedStyle(element, "::after");
        return {
          family: element.parentElement?.className || "",
          label: (element.textContent || "").trim(),
          markerMode: element.dataset.disclosureMarker || "toggle",
          beforeContent: before.content,
          afterContent: after.content,
          listStyleType: getComputedStyle(element).listStyleType,
          transitionDuration: [before.transitionDuration, after.transitionDuration],
          animationName: [before.animationName, after.animationName],
        };
      });
      const accessibilityTree = await summary.ariaSnapshot();
      await summary.evaluate((element) => {
        if (element.parentElement instanceof HTMLDetailsElement) {
          element.parentElement.open = true;
        }
      });
      const open = await summary.evaluate((element) => {
        const before = getComputedStyle(element, "::before");
        const after = getComputedStyle(element, "::after");
        return {
          beforeContent: before.content,
          afterContent: after.content,
        };
      });
      await summary.evaluate((element, shouldOpen) => {
        if (element.parentElement instanceof HTMLDetailsElement) {
          element.parentElement.open = shouldOpen;
        }
      }, originalOpen);
      disclosures.push({ index, closed, open, accessibilityTree });
    }
    const snapshot = await page.evaluate(() => {
      const controls = ["#themeBtn", "#dropZone", ".note-item"].map((selector) => {
        const element = document.querySelector(selector) || document.querySelector("#notepadNewBtn");
        const style = getComputedStyle(element);
        return {
          selector,
          transitionDuration: style.transitionDuration,
          animationName: style.animationName,
        };
      });
      return { controls };
    });
    await page.emulateMedia({ reducedMotion: "no-preference" });

    const disclosureMotionActive = disclosures.some((item) => (
      item.closed.transitionDuration.some((value) => value !== "0s") ||
      item.closed.animationName.some((value) => value !== "none")
    ));
    if (
      disclosureMotionActive ||
      snapshot.controls.some((item) => item.transitionDuration !== "0s" || item.animationName !== "none")
    ) {
      throw new Error(`Reduced-motion styles remain active: ${JSON.stringify({ disclosures, ...snapshot })}`);
    }
    if (disclosures.some((item) => (
      item.closed.markerMode !== "none" && (
      !`${item.closed.beforeContent} ${item.closed.afterContent}`.includes("[+]") ||
      item.closed.listStyleType !== "none"
      )
    ))) {
      throw new Error(`Closed disclosure markers are not accessibility-silent [+]: ${JSON.stringify(disclosures)}`);
    }
    if (disclosures.some((item) => (
      item.closed.markerMode !== "none" &&
      !`${item.open.beforeContent} ${item.open.afterContent}`.includes("[-]")
    ))) {
      throw new Error(`Open disclosure markers are not [-]: ${JSON.stringify(disclosures)}`);
    }
    if (disclosures.some((item) => (
      item.closed.markerMode === "none" &&
      /\[\+\]|\[-\]/.test(
        `${item.closed.beforeContent} ${item.closed.afterContent} ` +
        `${item.open.beforeContent} ${item.open.afterContent}`
      )
    ))) {
      throw new Error(`Marker-free disclosure generated a toggle marker: ${JSON.stringify(disclosures)}`);
    }
    if (disclosures.some((item) => /[▸▾▶▼]|\[\+\]|\[-\]/.test(item.accessibilityTree))) {
      throw new Error(`Disclosure accessibility tree contains a generated marker: ${JSON.stringify(disclosures)}`);
    }
    return { disclosures, ...snapshot };
  }

  async function assertOutputLiveRegionContracts(timeout = 10000) {
    await waitForPageCondition(
      "assertOutputLiveRegionContracts",
      () => {
        const panelIds = ["responseArea", "uploadResponseArea", "opsecResponseArea"];
        const liveIds = [
          "responseAreaLive",
          "uploadResponseAreaLive",
          "filesResponseAreaLive",
          "filesToastLive",
          "opsecResponseAreaLive",
        ];

        const panelsOk = panelIds.every((id) => {
          const panel = document.getElementById(id);
          return Boolean(panel && !panel.hasAttribute("aria-live"));
        });

        const liveOk = liveIds.every((id) => {
          const region = document.getElementById(id);
          return Boolean(
            region &&
            region.getAttribute("role") === "status" &&
            region.getAttribute("aria-live") === "polite" &&
            region.getAttribute("aria-atomic") === "true"
          );
        });

        const opsecWarning = document.getElementById("opsecSizeWarning");
        const opsecWarningOk = Boolean(
          opsecWarning &&
          opsecWarning.getAttribute("role") === "status" &&
          opsecWarning.getAttribute("aria-live") === "polite" &&
          opsecWarning.getAttribute("aria-atomic") === "true"
        );

        const notepadSaveIndicator = document.getElementById("notepadSaveIndicator");
        const notepadConnStatus = document.getElementById("notepadConnStatus");
        const notepadConnStatusText = document.getElementById("notepadConnStatusText");
        const notepadStatusOk = [notepadSaveIndicator, notepadConnStatus].every((region) =>
          Boolean(
            region &&
            region.getAttribute("role") === "status" &&
            region.getAttribute("aria-live") === "polite" &&
            region.getAttribute("aria-atomic") === "true"
          )
        ) && Boolean(notepadConnStatusText);

        const filesSummary = document.querySelector('[data-tool-summary-scope="files"]');
        const filesSummaryOk = Boolean(
          filesSummary &&
          filesSummary.getAttribute("aria-labelledby") === "filesResultTitle" &&
          !document.querySelector('[data-exchange-scope="files"]')
        );

        return panelsOk && liveOk && filesSummaryOk && opsecWarningOk && notepadStatusOk;
      },
      null,
      timeout
    );
  }

  async function assertStaticUiAssetsLoaded(timeout = 10000) {
    const assets = await page.evaluate(async () => {
      const urls = Array.from(document.querySelectorAll('script[src], link[rel="stylesheet"][href]'))
        .map((element) => element.getAttribute("src") || element.getAttribute("href"))
        .filter((url) => url && url.startsWith("/static/"));

      return Promise.all(urls.map(async (url) => {
        const response = await fetch(url, { cache: "no-store" });
        const body = await response.text();
        const assetPath = url.split("?")[0].split("#")[0];
        return {
          url,
          assetPath,
          ok: response.ok,
          status: response.status,
          bodyLength: body.length,
          containsInspectorApi:
            assetPath === "/static/ui/inspector.js" &&
            body.includes("app.registerService('inspector'"),
        };
      }));
    });

    const failed = assets.filter((asset) => !asset.ok || asset.bodyLength === 0);
    if (failed.length > 0) {
      throw new Error(`Static UI asset request failed: ${JSON.stringify(failed)}`);
    }
    const inspectorAsset = assets.find((asset) => asset.assetPath === "/static/ui/inspector.js");
    if (!inspectorAsset || !inspectorAsset.containsInspectorApi) {
      throw new Error("Inspector asset does not contain setExchangeInspector");
    }

    await waitForPageCondition(
      "inspector API loaded",
      () => {
        const exchangeScopes = ["upload", "opsec", "notepad"];
        const filesSummary = document.querySelector('[data-tool-summary-scope="files"]');
        const app = window.XferryApp;
        const inspector = app?.service("inspector");
        return Boolean(
          inspector &&
          typeof inspector.setInspector === "function" &&
          typeof inspector.getAreaRawText === "function" &&
          exchangeScopes.every((scope) => {
            const root = document.querySelector(`[data-exchange-scope="${scope}"]`);
            return root && typeof root.dataset.exchangePhase === "string" && root.dataset.exchangePhase.length > 0;
          }) &&
          filesSummary
        );
      },
      null,
      timeout
    );
  }

  async function assertApplicationModuleContract() {
    const contract = await page.evaluate(() => {
      const app = window.XferryApp;
      if (!app) {
        throw new Error("XferryApp namespace is unavailable");
      }

      const surface = app.describe();
      const accidentalGlobals = [
        "sendCustomRequest",
        "setExchangeInspector",
        "filesToUpload",
        "uploadMethod",
        "requestPreviewMode",
        "notepadIsDirty",
        "notepadSave",
        "browseDirectory",
        "showConfirmDialog",
      ].filter((name) => Object.prototype.hasOwnProperty.call(window, name));

      let unknownEventRejected = false;
      let unknownCommandRejected = false;
      try {
        app.emit("unknown.event");
      } catch (_error) {
        unknownEventRejected = true;
      }
      try {
        app.invoke("upload", "unknown-command");
      } catch (_error) {
        unknownCommandRejected = true;
      }

      return {
        surface,
        accidentalGlobals,
        unexpectedGlobals: app.unexpectedGlobals([
          "__xferryBrowserClipboardText",
          "__xferryClipboardMockInstalled",
        ]),
        unknownEventRejected,
        unknownCommandRejected,
        namespaceWritable: Object.getOwnPropertyDescriptor(window, "XferryApp")?.writable,
        workflowStates: Object.fromEntries(
          ["upload", "requests", "files", "advanced", "notepad"].map((name) => [
            name,
            app.getState(name),
          ])
        ),
      };
    });

    const expectedWorkflows = ["upload", "requests", "files", "advanced", "notepad"];
    const missingWorkflows = expectedWorkflows.filter(
      (name) => !Array.isArray(contract.surface.workflows[name])
    );
    if (
      contract.accidentalGlobals.length > 0 ||
      contract.unexpectedGlobals.length > 0 ||
      missingWorkflows.length > 0 ||
      !contract.unknownEventRejected ||
      !contract.unknownCommandRejected ||
      contract.namespaceWritable !== false
    ) {
      throw new Error(
        `Application module contract failed: ${JSON.stringify({
          accidentalGlobals: contract.accidentalGlobals,
          unexpectedGlobals: contract.unexpectedGlobals,
          missingWorkflows,
          unknownEventRejected: contract.unknownEventRejected,
          unknownCommandRejected: contract.unknownCommandRejected,
          namespaceWritable: contract.namespaceWritable,
        })}`
      );
    }

    const serializedStates = JSON.stringify(contract.workflowStates).toLowerCase();
    for (const forbiddenKey of ["sessionid", "derivedkey", "notebody", "filename", "title"]) {
      if (serializedStates.includes(forbiddenKey)) {
        throw new Error(`Workflow state snapshot exposes forbidden key: ${forbiddenKey}`);
      }
    }
  }

  async function assertSafeUserDataListRendering() {
    const result = await page.evaluate(async () => {
      const app = window.XferryApp;
      const payload = '<img src=x onerror="window.__xferryListXss=true">.txt';

      app.invoke(
        "upload",
        "handle-files",
        [new File(["safe"], payload, { type: "text/plain" })]
      );
      const uploadName = document.querySelector("#fileList .file-name");
      const uploadSafe = Boolean(
        uploadName &&
        uploadName.textContent === payload &&
        uploadName.children.length === 0 &&
        !document.querySelector("#fileList img, #fileList script")
      );
      document.querySelector("#fileList [data-remove-index]")?.click();

      const http = app.service("http");
      let originalAdapter = null;
      const injectedInfoAdapter = async (method, url, ...args) => {
        if (method === "INFO") {
          return new Response(
            JSON.stringify({
              entry: { kind: "directory", path: "/" },
              page: { total_items: 1 },
              contents: [{ name: payload, kind: "file" }],
            }),
            {
              status: 200,
              statusText: "OK",
              headers: { "Content-Type": "application/json" },
            }
          );
        }
        return originalAdapter(method, url, ...args);
      };
      originalAdapter = http["set-adapter"](injectedInfoAdapter);
      try {
        document.getElementById("browsePathInput").value = "/";
        await app.invoke("files", "browse");
      } finally {
        http["set-adapter"](originalAdapter);
      }

      const serverName = document.querySelector("#serverFiles .file-name");
      const filesSafe = Boolean(
        serverName &&
        serverName.textContent === payload &&
        serverName.children.length === 0 &&
        !document.querySelector("#serverFiles img, #serverFiles script")
      );
      await app.invoke("files", "browse");

      return {
        uploadSafe,
        filesSafe,
        executed: Boolean(window.__xferryListXss),
      };
    });

    if (!result.uploadSafe || !result.filesSafe || result.executed) {
      throw new Error(`Unsafe user-data list rendering: ${JSON.stringify(result)}`);
    }
  }

  async function assertFilesStaleBrowseGuard() {
    const result = await page.evaluate(async () => {
      const app = window.XferryApp;
      const http = app.service("http");
      const pending = new Map();
      let originalAdapter = null;
      const delayedInfoAdapter = (method, url, ...args) => {
        if (method !== "INFO") {
          return originalAdapter(method, url, ...args);
        }
        return new Promise((resolve) => {
          pending.set(new URL(String(url), location.href).pathname, resolve);
        });
      };
      originalAdapter = http["set-adapter"](delayedInfoAdapter);

      const pathInput = document.getElementById("browsePathInput");
      pathInput.value = "/first";
      const firstBrowse = app.invoke("files", "browse");
      pathInput.value = "/second";
      const secondBrowse = app.invoke("files", "browse");

      const release = (path, name) => {
        const resolve = pending.get(path);
        if (!resolve) {
          throw new Error(`Missing delayed INFO request for ${path}`);
        }
        resolve(new Response(
          JSON.stringify({
            entry: { kind: "directory", path },
            page: { total_items: 1 },
            contents: [{ name, kind: "file" }],
          }),
          {
            status: 200,
            statusText: "OK",
            headers: { "Content-Type": "application/json" },
          }
        ));
      };

      release("/second", "second.txt");
      await secondBrowse;
      release("/first", "stale-first.txt");
      await firstBrowse;
      http["set-adapter"](originalAdapter);

      const renderedNames = Array.from(
        document.querySelectorAll("#serverFiles .file-name")
      ).map((element) => element.textContent);

      pathInput.value = "/";
      await app.invoke("files", "browse");
      return { renderedNames };
    });

    if (
      result.renderedNames.length !== 1 ||
      result.renderedNames[0] !== "second.txt"
    ) {
      throw new Error(`Stale Files browse overwrote current state: ${JSON.stringify(result)}`);
    }
  }

  async function assertFilesDeleteTargetEncodingContract(timeout = 15000) {
    const singleName = "single #?.txt";
    const bulkNames = ["bulk-one #?.txt", "bulk-two ?#.txt"];
    await page.evaluate(([single, bulk]) => {
      const app = window.XferryApp;
      const http = app.service("http");
      const state = {
        items: [single, ...bulk].map((name, index) => ({
          name,
          kind: "file",
        })),
        deleteNames: [single, ...bulk],
        deleteTargets: [],
      };
      let originalAdapter = null;
      const adapter = async (method, url, ...args) => {
        const target = new URL(String(url), location.href);
        const decodedPathname = decodeURIComponent(target.pathname);
        if (method === "INFO" && decodedPathname === "/delete-wire-contract") {
          return new Response(JSON.stringify({
            entry: { kind: "directory", path: "/delete-wire-contract" },
            page: { total_items: state.items.length },
            contents: state.items,
          }), {
            status: 200,
            statusText: "OK",
            headers: { "Content-Type": "application/json" },
          });
        }
        if (method === "DELETE") {
          const expectedName = state.deleteNames[state.deleteTargets.length];
          state.deleteTargets.push({
            raw: String(url),
            pathname: target.pathname,
            search: target.search,
            hash: target.hash,
            expectedName,
          });
          state.items = state.items.filter(item => item.name !== expectedName);
          return new Response(JSON.stringify({
            deleted_file: { name: expectedName, path: `/delete-wire-contract/${expectedName}` },
          }), {
            status: 200,
            statusText: "OK",
            headers: { "Content-Type": "application/json" },
          });
        }
        return originalAdapter(method, url, ...args);
      };
      originalAdapter = http["set-adapter"](adapter);
      window.__filesDeleteTargetContract = { state, originalAdapter };
      document.getElementById("browsePathInput").value = "/delete-wire-contract";
    }, [singleName, bulkNames]);

    try {
      await page.locator("#tab-files").click();
      await waitForTabState("files", { focused: true });
      await page.locator("#browsePathInput").fill("/delete-wire-contract");
      await page.locator("#browseBtn").click();
      await waitForPageCondition(
        "special-path DELETE fixture rendered",
        ([names]) => names.every(name => (
          Array.from(document.querySelectorAll("#serverFiles .file-name"))
            .some(node => node.textContent === name)
        )),
        [[singleName, ...bulkNames]],
        timeout
      );

      const singlePath = encodeURIComponent(`/delete-wire-contract/${singleName}`);
      const singleDelete = page.locator(
        `#serverFiles [data-file-action="delete"][data-path="${singlePath}"]`
      );
      await singleDelete.locator("xpath=ancestor::details[1]").locator(":scope > summary").click();
      await singleDelete.click();
      await confirmAppDialog(singleName, timeout);
      await waitForPageCondition(
        "single special-path DELETE completed",
        ([targetPath]) => !document.querySelector(`#serverFiles [data-path="${targetPath}"]`),
        [singlePath],
        timeout
      );

      for (const name of bulkNames) {
        const encodedPath = encodeURIComponent(`/delete-wire-contract/${name}`);
        await page.locator(`[data-file-select][data-path="${encodedPath}"]`).check();
      }
      await page.locator("#deleteSelectedUploadsBtn").click();
      await confirmAppDialog(/bulk-one|bulk-two/, timeout);
      await waitForPageCondition(
        "bulk special-path DELETE completed",
        () => window.__filesDeleteTargetContract?.state.deleteTargets.length === 3,
        null,
        timeout
      );

      const result = await page.evaluate(() => (
        window.__filesDeleteTargetContract.state.deleteTargets.map(target => ({ ...target }))
      ));
      const expectedNames = [singleName, ...bulkNames];
      const expectedPathnames = expectedNames.map(name => (
        `/delete-wire-contract/${encodeURIComponent(name)}`
      ));
      if (result.length !== expectedNames.length || result.some((target, index) => (
        target.pathname !== expectedPathnames[index] ||
        target.search !== "" ||
        target.hash !== "" ||
        target.expectedName !== expectedNames[index]
      ))) {
        throw new Error(`Files DELETE target encoding failed: ${JSON.stringify({ result, expectedPathnames })}`);
      }
      return result;
    } finally {
      await page.evaluate(() => {
        const contract = window.__filesDeleteTargetContract;
        if (!contract) return;
        window.XferryApp.service("http")["set-adapter"](contract.originalAdapter);
        delete window.__filesDeleteTargetContract;
      });
      await page.locator("#tab-upload").click();
      await waitForTabState("upload", { focused: true });
    }
  }

  async function assertFilesInfoLastResultWinsContract(timeout = 15000) {
    const names = ["older-info.txt", "latest-info.txt"];
    await switchLanguage("en");
    await page.evaluate(([fixtureNames]) => {
      const app = window.XferryApp;
      const http = app.service("http");
      const state = { pending: {}, consumed: [] };
      let originalAdapter = null;
      const adapter = async (method, url, ...args) => {
        const pathname = decodeURIComponent(new URL(String(url), location.href).pathname);
        if (method === "INFO" && pathname === "/info-race") {
          return new Response(JSON.stringify({
            entry: { kind: "directory", path: "/info-race" },
            page: { total_items: fixtureNames.length },
            contents: fixtureNames.map((name, index) => ({
              name,
              kind: "file",
            })),
          }), {
            status: 200,
            statusText: "OK",
            headers: { "Content-Type": "application/json" },
          });
        }
        if (method === "INFO" && pathname.startsWith("/info-race/")) {
          return new Promise(resolve => {
            state.pending[pathname] = () => resolve({
              ok: true,
              status: 200,
              statusText: "OK",
              headers: new Headers({ "Content-Type": "application/json" }),
              text: async () => {
                state.consumed.push(pathname);
                const name = pathname.split("/").pop();
                return JSON.stringify({ entry: {
                  name,
                  path: pathname,
                  kind: "file",
                  size_bytes: name === fixtureNames[0] ? 1 : 2,
                  size_human: name === fixtureNames[0] ? "1 B" : "2 B",
                  content_type: "text/plain",
                  extension: ".txt",
                  created_at: "2026-08-01T12:00:00Z",
                  modified_at: "2026-08-01T12:01:00Z",
                } });
              },
            });
          });
        }
        return originalAdapter(method, url, ...args);
      };
      originalAdapter = http["set-adapter"](adapter);
      window.__filesInfoRaceContract = { state, originalAdapter };
      document.getElementById("browsePathInput").value = "/info-race";
    }, [names]);

    let contractFailure = null;
    try {
      await page.locator("#tab-files").click();
      await waitForTabState("files", { focused: true });
      await page.locator("#browsePathInput").fill("/info-race");
      await page.locator("#browseBtn").click();
      await waitForPageCondition(
        "out-of-order INFO fixture rendered",
        ([fixtureNames]) => fixtureNames.every(name => (
          Array.from(document.querySelectorAll("#serverFiles .file-name"))
            .some(node => node.textContent === name)
        )),
        [names],
        timeout
      );

      const triggerInfo = async (name) => {
        const encodedPath = encodeURIComponent(`/info-race/${name}`);
        const trigger = page.locator(
          `#serverFiles [data-file-details-trigger][data-path="${encodedPath}"]`
        );
        await trigger.click();
        await waitForPageCondition(
          `pending INFO captured (${name})`,
          ([path]) => typeof window.__filesInfoRaceContract?.state.pending[path] === "function",
          [`/info-race/${name}`],
          timeout
        );
        return encodedPath;
      };
      const releaseInfo = async (name) => {
        await page.evaluate(([path]) => {
          const pending = window.__filesInfoRaceContract.state.pending[path];
          delete window.__filesInfoRaceContract.state.pending[path];
          pending();
        }, [`/info-race/${name}`]);
      };

      const olderEncodedPath = await triggerInfo(names[0]);
      const latestEncodedPath = await triggerInfo(names[1]);
      await releaseInfo(names[1]);
      await waitForPageCondition(
        "latest INFO renders expanded inline details",
        ([latestName, latestPath]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${latestPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          return Boolean(
            trigger?.getAttribute("aria-expanded") === "true" &&
            panel &&
            !panel.hidden &&
            panel.getAttribute("role") === "region" &&
            panel.getAttribute("aria-busy") === "false" &&
            (panel.innerText || panel.textContent || "").includes(latestName)
          );
        },
        [names[1], latestEncodedPath],
        timeout
      );

      await releaseInfo(names[0]);
      await waitForPageCondition(
        "older INFO response cannot replace latest inline details",
        ([olderName, latestName, olderPath, latestPath]) => {
          const contract = window.__filesInfoRaceContract;
          const summary = document.querySelector('[data-tool-summary-scope="files"]');
          const olderTrigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${olderPath}"]`
          );
          const latestTrigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${latestPath}"]`
          );
          const latestPanel = latestTrigger?.getAttribute("aria-controls")
            ? document.getElementById(latestTrigger.getAttribute("aria-controls"))
            : null;
          const latestText = latestPanel?.innerText || latestPanel?.textContent || "";
          return Boolean(
            contract?.state.consumed.join("|") === `/info-race/${latestName}|/info-race/${olderName}` &&
            summary?.dataset.phase === "empty" &&
            olderTrigger?.getAttribute("aria-expanded") === "false" &&
            latestTrigger?.getAttribute("aria-expanded") === "true" &&
            latestPanel &&
            !latestPanel.hidden &&
            latestText.includes(latestName) &&
            !latestText.includes(olderName) &&
            !document.querySelector("#appDialog [role='dialog'], #appDialog [role='alertdialog']")
          );
        },
        [names[0], names[1], olderEncodedPath, latestEncodedPath],
        timeout
      );

      const olderTrigger = page.locator(
        `#serverFiles [data-file-details-trigger][data-path="${olderEncodedPath}"]`
      );
      await olderTrigger.click();
      await waitForPageCondition(
        "older INFO pending before collapse",
        ([path]) => typeof window.__filesInfoRaceContract?.state.pending[path] === "function",
        [`/info-race/${names[0]}`],
        timeout
      );
      await olderTrigger.click();
      await waitForPageCondition(
        "collapsing pending INFO hides stale panel",
        ([targetPath]) => Boolean(
          document.querySelector(`#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`)
            ?.getAttribute("aria-expanded") === "false" &&
          !Array.from(document.querySelectorAll("#serverFiles .file-row__details-panel"))
            .some(panel => !panel.hidden)
        ),
        [olderEncodedPath],
        timeout
      );
      await releaseInfo(names[0]);
      await waitForPageCondition(
        "late collapsed INFO cannot reopen inline details",
        ([olderName]) => Boolean(
          window.__filesInfoRaceContract?.state.consumed.filter(path => path.endsWith(`/${olderName}`)).length === 2 &&
          !Array.from(document.querySelectorAll("#serverFiles .file-row__details-panel"))
            .some(panel => !panel.hidden) &&
          !document.querySelector("#appDialog [role='dialog'], #appDialog [role='alertdialog']")
        ),
        [names[0]],
        timeout
      );
      return page.evaluate(() => ({
        consumed: window.__filesInfoRaceContract.state.consumed.slice(),
      }));
    } catch (error) {
      contractFailure = error;
      throw error;
    } finally {
      try {
        await page.evaluate(() => {
          const contract = window.__filesInfoRaceContract;
          try {
            if (contract) {
              window.XferryApp.service("http")["set-adapter"](contract.originalAdapter);
            }
          } finally {
            delete window.__filesInfoRaceContract;
          }
        });
        if (await page.locator("#appDialog").count()) {
          await page.keyboard.press("Escape");
          await page.locator("#appDialog").waitFor({ state: "detached", timeout });
        }
        await switchLanguage("ru");
        await page.locator("#tab-upload").click();
        await waitForTabState("upload", { focused: true });
      } catch (cleanupError) {
        if (!contractFailure) {
          throw cleanupError;
        }
        contractFailure.message += `\nFiles INFO race cleanup also failed: ${cleanupError.message}`;
      }
    }
  }

  async function assertFilesCompactExplorerContract(timeout = 15000) {
    const longName = `long-${"segment-".repeat(18)}.txt`;
    await switchLanguage("ru");
    await page.setViewportSize({ width: 1440, height: 1024 });
    let contractFailure = null;
    try {
    await page.evaluate(([fixtureLongName]) => {
      const app = window.XferryApp;
      const http = app.service("http");
      const state = {
        infoCalls: 0,
        infoRequests: [],
        detailRequests: [],
        pendingDetailPaths: {},
        pendingDetails: {},
        detailFailPaths: {},
        deleteCalls: [],
        fail: false,
        hostileExecuted: false,
        totalItems: 9,
        items: [
          {
            name: "zeta.txt",
            kind: "file",
            inspection: {
              mime_type: "text/plain",
              mime_source: "signature",
              content_state: "recognized",
              warning: null,
              reasons: [],
            },
          },
          { name: "Folder", kind: "directory" },
          {
            name: fixtureLongName,
            kind: "file",
            inspection: {
              mime_type: "application/octet-stream",
              mime_source: "unknown",
              content_state: "opaque",
              warning: "possible_encrypted_or_packed",
              reasons: ["unrecognized_binary"],
            },
          },
          {
            name: "alpha.txt",
            kind: "file",
            inspection: {
              mime_type: "application/pdf",
              mime_source: "signature",
              content_state: "recognized",
              warning: "extension_mismatch",
              reasons: ["extension_mismatch"],
            },
          },
        ],
      };
      let originalAdapter = null;
      const adapter = async (method, url, ...args) => {
        const requestUrl = new URL(String(url), location.href);
        const pathname = decodeURIComponent(requestUrl.pathname);
        if (method === "INFO") {
          state.infoRequests.push({ pathname, search: requestUrl.search });
        }
        if (method === "INFO" && pathname === "/compact-contract") {
          state.infoCalls += 1;
          if (state.initialRelease) {
            return new Promise(resolve => {
              state.initialRelease = resolve;
            });
          }
          if (state.pendingRelease) {
            return new Promise(resolve => {
              state.pendingRelease = resolve;
            });
          }
          if (state.fail) {
            return new Response(
              '<img src=x onerror="window.__filesCompactHostileExecuted=true">',
              {
                status: 503,
                statusText: "Service unavailable",
                headers: { "Content-Type": "text/html", "X-Request-ID": "files-compact-503" },
              }
            );
          }
          return new Response(JSON.stringify({
            entry: { kind: "directory", path: "/compact-contract" },
            page: { total_items: state.totalItems },
            contents: state.items,
          }), {
            status: 200,
            statusText: "OK",
            headers: { "Content-Type": "application/json" },
          });
        }
        if (method === "INFO" && pathname === "/compact-contract/Folder") {
          return new Response(JSON.stringify({
            entry: { kind: "directory", path: "/compact-contract/Folder" },
            page: { total_items: 1 },
            contents: [{ name: "nested.txt", kind: "file" }],
          }), {
            status: 200,
            statusText: "OK",
            headers: { "Content-Type": "application/json" },
          });
        }
        if (method === "INFO" && pathname.startsWith("/compact-contract/")) {
          state.detailRequests.push({ pathname, search: requestUrl.search });
          const name = pathname.split("/").pop();
          const item = state.items.find(candidate => candidate.name === name);
          const body = { entry: {
            name,
            path: pathname,
            kind: "file",
            size_bytes: 2,
            size_human: "2 B",
            content_type: "text/plain",
            extension: ".txt",
            created_at: "2026-08-01T10:00:00Z",
            modified_at: "2026-08-01T10:01:00Z",
          } };
          if (name !== "zeta.txt") {
            body.entry.inspection = item?.inspection;
          }
          const successResponse = () => new Response(JSON.stringify(body), {
            status: 200,
            statusText: "OK",
            headers: { "Content-Type": "application/json" },
          });
          if (state.detailFailPaths[pathname]) {
            return new Response(JSON.stringify({ error: {
              code: "resource_unavailable", message: "detail fixture unavailable", field: null, details: {},
            } }), {
              status: 503,
              statusText: "Service unavailable",
              headers: { "Content-Type": "application/json" },
            });
          }
          if (state.pendingDetailPaths[pathname]) {
            return new Promise(resolve => {
              state.pendingDetails[pathname] = () => resolve(successResponse());
            });
          }
          return successResponse();
        }
        if (method === "DELETE" && pathname.startsWith("/compact-contract/")) {
          state.deleteCalls.push(pathname);
          const name = pathname.split("/").pop();
          state.items = state.items.filter(item => item.name !== name);
          return new Response(JSON.stringify({
            deleted_file: { name, path: pathname },
          }), {
            status: 200,
            statusText: "OK",
            headers: { "Content-Type": "application/json" },
          });
        }
        return originalAdapter(method, url, ...args);
      };
      originalAdapter = http["set-adapter"](adapter);
      window.__filesCompactContract = { state, originalAdapter };
      window.__filesCompactHostileExecuted = false;

      state.initialRelease = true;
      document.getElementById("browsePathInput").value = "/compact-contract";
      window.__filesCompactInitialBrowse = app.invoke("files", "browse");
    }, [longName]);

    await waitForPageCondition(
      "Files initial browse exposes loading state",
      () => {
        const list = document.getElementById("serverFiles");
        const message = list?.querySelector('[data-browse-phase="loading"][role="listitem"]');
        return Boolean(
          list?.getAttribute("role") === "list" &&
          list.getAttribute("aria-busy") === "true" &&
          list.dataset.browsePhase === "loading" &&
          message?.textContent.includes("/compact-contract")
        );
      },
      null,
      timeout
    );
    await page.evaluate(() => {
      const contract = window.__filesCompactContract;
      const release = contract.state.initialRelease;
      contract.state.initialRelease = false;
      release(new Response(
        '<img src=x onerror="window.__filesCompactHostileExecuted=true">',
        {
          status: 503,
          statusText: "Service unavailable",
          headers: { "Content-Type": "text/html" },
        }
      ));
    });
    await page.evaluate(() => window.__filesCompactInitialBrowse);
    await waitForPageCondition(
      "Files initial error is safe and has no stale list",
      () => {
        const list = document.getElementById("serverFiles");
        const message = list?.querySelector('[data-browse-phase="error"][role="listitem"]');
        const card = document.querySelector("#filesHttpErrorHost .http-error-card");
        return Boolean(
          list?.getAttribute("aria-busy") === "false" &&
          message &&
          card?.textContent.includes("503 Service unavailable") &&
          !card.querySelector("img") &&
          !window.__filesCompactHostileExecuted
        );
      },
      null,
      timeout
    );
    await page.evaluate(() => window.XferryApp.service("http-errors").close("filesHttpErrorHost"));

    await page.locator("#tab-files").click();
    await waitForTabState("files", { focused: true });
    await waitForPageCondition(
      "Files tab automatic browse settles before explicit browse contract",
      () => window.__filesCompactContract.state.infoCalls >= 2,
      null,
      timeout
    );
    await page.evaluate(() => {
      window.__filesCompactContract.state.infoRequests = [];
    });
    await page.locator("#browsePathInput").fill("/compact-contract");
    await page.locator("#browseBtn").click();
    await waitForPageCondition(
      "Files compact fixture renders sorted list and N of M",
      ([fixtureLongName]) => {
        const list = document.getElementById("serverFiles");
        const rows = Array.from(list?.querySelectorAll(":scope > .uploaded-file") || []);
        const names = rows.map(row => row.querySelector(".file-name")?.textContent || "");
        const status = document.getElementById("filesBrowseStatus")?.textContent || "";
        const directory = rows[0];
        return Boolean(
          list?.getAttribute("role") === "list" &&
          list.getAttribute("aria-busy") === "false" &&
          rows.length === 4 &&
          rows.every(row => row.getAttribute("role") === "listitem") &&
          names.join("|") === `Folder|alpha.txt|${fixtureLongName}|zeta.txt` &&
          directory?.classList.contains("uploaded-file--dir") &&
          !directory.querySelector('[data-file-select]') &&
          list.querySelectorAll('[data-file-select]').length === 3 &&
          status.includes("/compact-contract") &&
          status.includes("Показано 4 из 9")
        );
      },
      [longName],
      timeout
    );

    const inspectionContract = await page.evaluate(([fixtureLongName]) => {
      const contract = window.__filesCompactContract;
      const rowFor = name => Array.from(
        document.querySelectorAll("#serverFiles .uploaded-file--file")
      ).find(row => row.querySelector(".file-name")?.textContent === name);
      const alpha = rowFor("alpha.txt");
      const zeta = rowFor("zeta.txt");
      const opaque = rowFor(fixtureLongName);
      const hintFor = row => row?.querySelector(".file-row__xor-hint");
      const xorFor = row => row?.querySelector('[data-file-action="decrypt-xor"]');
      const opaqueHint = hintFor(opaque);
      const opaqueXor = xorFor(opaque);
      const mismatchHint = hintFor(alpha);
      const mismatchXor = xorFor(alpha);
      const neutralHint = hintFor(zeta);
      const neutralXor = xorFor(zeta);
      return {
        infoRequests: contract.state.infoRequests.slice(),
        alphaMime: alpha?.querySelector(".file-inspection__mime")?.textContent || "",
        alphaWarning: alpha?.querySelector(".file-inspection__warning")?.textContent || "",
        opaqueMime: opaque?.querySelector(".file-inspection__mime")?.textContent || "",
        opaqueWarning: opaque?.querySelector(".file-inspection__warning")?.textContent || "",
        opaqueHint: opaqueHint?.textContent || "",
        opaqueHintId: opaqueHint?.id || "",
        opaqueDescribedBy: opaqueXor?.getAttribute("aria-describedby") || "",
        opaqueCaution: opaqueXor?.classList.contains("file-row__action-xor--caution") || false,
        mismatchHint: mismatchHint?.textContent || "",
        mismatchDescribedBy: mismatchXor?.getAttribute("aria-describedby") || "",
        mismatchCaution: mismatchXor?.classList.contains("file-row__action-xor--caution") || false,
        neutralHint: neutralHint?.textContent || "",
        neutralDescribedBy: neutralXor?.getAttribute("aria-describedby") || "",
        neutralCaution: neutralXor?.classList.contains("file-row__action-xor--caution") || false,
        warningCount: document.querySelectorAll("#serverFiles .file-inspection__warning").length,
      };
    }, [longName]);
    if (
      inspectionContract.infoRequests.length !== 1 ||
      inspectionContract.infoRequests[0]?.pathname !== "/compact-contract" ||
      inspectionContract.infoRequests[0]?.search !== "?inspect=true" ||
      inspectionContract.alphaMime !== "MIME: application/pdf · по сигнатуре" ||
      inspectionContract.alphaWarning !== "Расширение не совпадает с содержимым" ||
      inspectionContract.opaqueMime !== "MIME: application/octet-stream · источник не определён" ||
      inspectionContract.opaqueWarning !== "Возможно зашифрован или упакован" ||
      inspectionContract.opaqueHint !== "Формат не распознан: пробуйте, только если использовался XOR." ||
      !inspectionContract.opaqueHintId ||
      inspectionContract.opaqueDescribedBy !== inspectionContract.opaqueHintId ||
      !inspectionContract.opaqueCaution ||
      inspectionContract.mismatchHint !== "Только для файлов, зашифрованных XOR." ||
      !inspectionContract.mismatchDescribedBy ||
      inspectionContract.mismatchCaution ||
      inspectionContract.neutralHint !== "Только для файлов, зашифрованных XOR." ||
      !inspectionContract.neutralDescribedBy ||
      inspectionContract.neutralCaution ||
      inspectionContract.warningCount !== 2
    ) {
      throw new Error(`Files inspection browse contract failed: ${JSON.stringify(inspectionContract)}`);
    }

    const baseVisual = await page.evaluate(([fixtureLongName]) => {
      const list = document.getElementById("serverFiles");
      const fileRows = Array.from(list.querySelectorAll(".uploaded-file--file"));
      const labels = fileRows.map(row => row.querySelector(".file-select"));
      const detailTriggers = fileRows.map(row => row.querySelector(".file-row__details-trigger"));
      const summaries = fileRows.map(row => row.querySelector(".file-row__more > summary"));
      const primaryActions = fileRows.map(row => row.querySelector(".file-row__action-main"));
      const longRow = fileRows.find(row => row.querySelector(".file-name")?.textContent === fixtureLongName);
      const longNameElement = longRow?.querySelector(".file-name");
      const longRowRect = longRow?.getBoundingClientRect();
      const longNameRect = longNameElement?.getBoundingClientRect();
      const alphaLabel = labels.find(label => label?.getAttribute("aria-label")?.includes("alpha.txt"));
      alphaLabel?.querySelector("input")?.focus();
      const focusStyle = alphaLabel ? getComputedStyle(alphaLabel) : null;
      const targets = [...labels, ...detailTriggers, ...summaries, ...primaryActions]
        .filter(Boolean)
        .map(element => {
          const rect = element.getBoundingClientRect();
          return { width: rect.width, height: rect.height };
        });
      return {
        namedCheckboxes: labels.every(label => (
          label?.getAttribute("aria-label")?.includes(
            label.closest(".uploaded-file")?.querySelector(".file-name")?.textContent || ""
          )
        )),
        focusOutline: focusStyle?.outlineStyle || "none",
        focusWidth: parseFloat(focusStyle?.outlineWidth || "0"),
        targets,
        longWrapsInsideRow: Boolean(
          longRowRect && longNameRect && longNameRect.right <= longRowRect.right + 1
        ),
        listOverflow: list.scrollWidth > list.clientWidth + 1,
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      };
    }, [longName]);
    if (
      !baseVisual.namedCheckboxes ||
      baseVisual.focusOutline === "none" ||
      baseVisual.focusWidth < 3 ||
      baseVisual.targets.some(target => target.width < 44 || target.height < 44) ||
      !baseVisual.longWrapsInsideRow ||
      baseVisual.listOverflow ||
      baseVisual.documentOverflow
    ) {
      throw new Error(`Files compact semantics/layout contract failed: ${JSON.stringify(baseVisual)}`);
    }

    async function assertFilesSearchSortSelectionContract() {
      const expectedAsc = `Folder|alpha.txt|${longName}|zeta.txt`;
      const expectedDesc = `Folder|zeta.txt|${longName}|alpha.txt`;

      await waitForPageCondition(
        "Files search/sort/selection controls are wired",
        ([targetAsc]) => {
          const list = document.getElementById("serverFiles");
          const header = document.getElementById("filesListHeader");
          const selectVisible = document.getElementById("filesSelectVisibleCheckbox");
          const sortButton = document.getElementById("filesSortNameBtn");
          const search = document.getElementById("filesSearchInput");
          const clear = document.getElementById("filesSearchClearBtn");
          const globalActions = document.getElementById("filesGlobalActions");
          const filterStatus = document.getElementById("filesFilterStatus");
          const names = Array.from(list?.querySelectorAll(":scope > .uploaded-file") || [])
            .filter(row => !row.hidden && row.getClientRects().length > 0)
            .map(row => row.querySelector(".file-name")?.textContent || "");
          const badRoles = [header, ...Array.from(header?.children || [])]
            .filter(Boolean)
            .map(node => node.getAttribute("role"))
            .filter(Boolean);
          return Boolean(
            search &&
            clear &&
            globalActions &&
            filterStatus &&
            header &&
            header.hidden === false &&
            selectVisible &&
            !selectVisible.disabled &&
            !selectVisible.checked &&
            !selectVisible.indeterminate &&
            sortButton &&
            !document.getElementById("filesDangerZone") &&
            badRoles.length === 0 &&
            names.join("|") === targetAsc
          );
        },
        [expectedAsc],
        timeout
      );

      const alphaEncodedPath = encodeURIComponent("/compact-contract/alpha.txt");
      await page.locator(`#serverFiles [data-file-select][data-path="${alphaEncodedPath}"]`).check();
      await waitForPageCondition(
        "Files single selection is reflected before search",
        ([targetPath]) => {
          const checked = Array.from(document.querySelectorAll("#serverFiles [data-file-select]:checked"))
            .map(input => input.dataset.path || "");
          const selection = document.getElementById("filesSelectionBar");
          return Boolean(
            checked.length === 1 &&
            checked[0] === targetPath &&
            selection &&
            !selection.hidden
          );
        },
        [alphaEncodedPath],
        timeout
      );

      await page.locator("#filesSearchInput").fill("TA");
      await waitForPageCondition(
        "Files search filters loaded names case-insensitively and clears selection",
        () => {
          const visibleRows = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0);
          const names = visibleRows.map(row => row.querySelector(".file-name")?.textContent || "");
          const clear = document.getElementById("filesSearchClearBtn");
          const filterStatus = document.getElementById("filesFilterStatus");
          const selectVisible = document.getElementById("filesSelectVisibleCheckbox");
          const selection = document.getElementById("filesSelectionBar");
          return Boolean(
            document.getElementById("filesSearchInput")?.value === "TA" &&
            names.join("|") === "zeta.txt" &&
            clear &&
            !clear.hidden &&
            filterStatus &&
            filterStatus.textContent.includes("1") &&
            selectVisible &&
            !selectVisible.disabled &&
            !selectVisible.checked &&
            !selectVisible.indeterminate &&
            document.querySelectorAll("#serverFiles [data-file-select]:checked").length === 0 &&
            selection?.hidden === true
          );
        },
        null,
        timeout
      );

      await page.locator("#browseRefreshBtn").click();
      await waitForPageCondition(
        "Files search query persists through refresh",
        () => {
          const names = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0)
            .map(row => row.querySelector(".file-name")?.textContent || "");
          return Boolean(
            document.getElementById("filesSearchInput")?.value === "TA" &&
            names.join("|") === "zeta.txt"
          );
        },
        null,
        timeout
      );
      await switchLanguage("en");
      await waitForPageCondition(
        "Files search query persists through locale change",
        () => document.getElementById("filesSearchInput")?.value === "TA",
        null,
        timeout
      );
      await switchLanguage("ru");

      await page.locator("#filesSearchInput").fill("no-such-file");
      await waitForPageCondition(
        "Files search no-match state is distinct from empty folder",
        () => {
          const rows = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0);
          const message = document.querySelector("#serverFiles [data-browse-phase='filtered-empty'][role='listitem']");
          const filterStatus = document.getElementById("filesFilterStatus");
          return Boolean(
            rows.length === 0 &&
            message &&
            /no-such-file|совпад|match/i.test(message.textContent || "") &&
            filterStatus &&
            /0/.test(filterStatus.textContent || "")
          );
        },
        null,
        timeout
      );

      await page.locator("#filesSearchClearBtn").click();
      await waitForPageCondition(
        "Files search clear restores the full loaded list",
        ([targetAsc]) => {
          const names = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0)
            .map(row => row.querySelector(".file-name")?.textContent || "");
          return Boolean(
            document.getElementById("filesSearchInput")?.value === "" &&
            document.getElementById("filesSearchClearBtn")?.hidden === true &&
            names.join("|") === targetAsc
          );
        },
        [expectedAsc],
        timeout
      );

      await page.locator("#filesSortNameBtn").click();
      await waitForPageCondition(
        "Files name sort toggles descending with directories first and announces state",
        ([targetDesc]) => {
          const names = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0)
            .map(row => row.querySelector(".file-name")?.textContent || "");
          const sortButton = document.getElementById("filesSortNameBtn");
          const announced = [
            sortButton?.getAttribute("aria-label") || "",
            sortButton?.getAttribute("title") || "",
            document.getElementById("filesFilterStatus")?.textContent || "",
            document.getElementById("filesResponseAreaLive")?.textContent || "",
          ].join(" ");
          return Boolean(
            names.join("|") === targetDesc &&
            /(убыв|desc)/i.test(announced)
          );
        },
        [expectedDesc],
        timeout
      );

      await page.locator("#filesSelectVisibleCheckbox").check();
      await waitForPageCondition(
        "Files master checkbox selects visible files but not directories",
        () => {
          const visibleRows = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0);
          const checked = Array.from(document.querySelectorAll("#serverFiles [data-file-select]:checked"));
          const directory = visibleRows.find(row => row.classList.contains("uploaded-file--dir"));
          const master = document.getElementById("filesSelectVisibleCheckbox");
          const selectionCount = document.getElementById("filesSelectionCount")?.textContent || "";
          return Boolean(
            visibleRows.length === 4 &&
            checked.length === 3 &&
            !directory?.querySelector("[data-file-select]") &&
            master?.checked &&
            !master.indeterminate &&
            !master.disabled &&
            selectionCount.includes("3")
          );
        },
        null,
        timeout
      );

      await page.locator("#filesSearchInput").fill("zeta");
      await waitForPageCondition(
        "Files changing search clears prior bulk selection",
        () => {
          const names = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0)
            .map(row => row.querySelector(".file-name")?.textContent || "");
          const master = document.getElementById("filesSelectVisibleCheckbox");
          return Boolean(
            names.join("|") === "zeta.txt" &&
            document.querySelectorAll("#serverFiles [data-file-select]:checked").length === 0 &&
            document.getElementById("filesSelectionBar")?.hidden === true &&
            master &&
            !master.disabled &&
            !master.checked &&
            !master.indeterminate
          );
        },
        null,
        timeout
      );

      const zetaEncodedPath = encodeURIComponent("/compact-contract/zeta.txt");
      await page.locator("#filesSelectVisibleCheckbox").check();
      await waitForPageCondition(
        "Files master checkbox selects only the visible filtered file",
        ([targetPath]) => {
          const checked = Array.from(document.querySelectorAll("#serverFiles [data-file-select]:checked"))
            .map(input => input.dataset.path || "");
          const master = document.getElementById("filesSelectVisibleCheckbox");
          return Boolean(
            checked.length === 1 &&
            checked[0] === targetPath &&
            master?.checked &&
            !master.indeterminate
          );
        },
        [zetaEncodedPath],
        timeout
      );

      await page.locator("#filesSortNameBtn").click();
      await waitForPageCondition(
        "Files sorting preserves filtered selection",
        ([targetPath]) => {
          const checked = Array.from(document.querySelectorAll("#serverFiles [data-file-select]:checked"))
            .map(input => input.dataset.path || "");
          const names = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0)
            .map(row => row.querySelector(".file-name")?.textContent || "");
          return Boolean(
            document.getElementById("filesSearchInput")?.value === "zeta" &&
            names.join("|") === "zeta.txt" &&
            checked.length === 1 &&
            checked[0] === targetPath
          );
        },
        [zetaEncodedPath],
        timeout
      );

      await page.locator("#filesSearchInput").fill("Folder");
      await waitForPageCondition(
        "Files master checkbox disables when only directories are visible",
        () => {
          const visibleRows = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0);
          const names = visibleRows.map(row => row.querySelector(".file-name")?.textContent || "");
          const master = document.getElementById("filesSelectVisibleCheckbox");
          return Boolean(
            names.join("|") === "Folder" &&
            visibleRows[0]?.classList.contains("uploaded-file--dir") &&
            !visibleRows[0]?.querySelector("[data-file-select]") &&
            master &&
            master.disabled &&
            !master.checked &&
            !master.indeterminate
          );
        },
        null,
        timeout
      );

      await page.locator("#filesSearchClearBtn").click();
      await page.locator("#filesSearchInput").fill("alpha");
      await page.locator("#browseRefreshBtn").click();
      await waitForPageCondition(
        "Files search query persists through explicit refresh before path change",
        () => {
          const names = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0)
            .map(row => row.querySelector(".file-name")?.textContent || "");
          return Boolean(
            document.getElementById("filesSearchInput")?.value === "alpha" &&
            names.join("|") === "alpha.txt"
          );
        },
        null,
        timeout
      );

      await page.locator("#browsePathInput").fill("/compact-contract/Folder");
      await page.locator("#browseBtn").click();
      await waitForPageCondition(
        "Files search query resets when navigating to another path",
        () => {
          const names = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0)
            .map(row => row.querySelector(".file-name")?.textContent || "");
          return Boolean(
            document.getElementById("filesSearchInput")?.value === "" &&
            names.join("|") === "nested.txt"
          );
        },
        null,
        timeout
      );

      await page.locator("#browsePathInput").fill("/compact-contract");
      await page.locator("#browseBtn").click();
      await waitForPageCondition(
        "Files compact fixture restored after search/sort/selection contract",
        ([targetAsc]) => {
          const names = Array.from(document.querySelectorAll("#serverFiles > .uploaded-file"))
            .filter(row => !row.hidden && row.getClientRects().length > 0)
            .map(row => row.querySelector(".file-name")?.textContent || "");
          return Boolean(names.join("|") === targetAsc);
        },
        [expectedAsc],
        timeout
      );
    }

    await assertFilesSearchSortSelectionContract();

    async function assertInlineDetailsIdContract() {
      await page.evaluate(() => {
        const state = window.__filesCompactContract.state;
        state.items.push(
          { name: "collision.a", kind: "file" },
          { name: "collision_a", kind: "file" },
        );
        state.totalItems += 2;
      });
      await page.locator("#browseRefreshBtn").click();
      await waitForPageCondition(
        "Files inline details IDs remain unique for colliding punctuation",
        () => {
          const rowFor = name => Array.from(
            document.querySelectorAll("#serverFiles .uploaded-file--file")
          ).find(row => row.querySelector(".file-name")?.textContent === name);
          const dottedRow = rowFor("collision.a");
          const underscoredRow = rowFor("collision_a");
          const dottedTrigger = dottedRow?.querySelector("[data-file-details-trigger]");
          const underscoredTrigger = underscoredRow?.querySelector("[data-file-details-trigger]");
          const dottedPanel = dottedRow?.querySelector(".file-row__details-panel");
          const underscoredPanel = underscoredRow?.querySelector(".file-row__details-panel");
          const controlsMatch = trigger => (
            trigger?.getAttribute("aria-controls") &&
            document.getElementById(trigger.getAttribute("aria-controls"))
          );
          return Boolean(
            dottedTrigger &&
            underscoredTrigger &&
            dottedPanel &&
            underscoredPanel &&
            dottedTrigger.id !== underscoredTrigger.id &&
            dottedPanel.id !== underscoredPanel.id &&
            controlsMatch(dottedTrigger) === dottedPanel &&
            controlsMatch(underscoredTrigger) === underscoredPanel &&
            dottedPanel.getAttribute("aria-labelledby") === dottedTrigger.id &&
            underscoredPanel.getAttribute("aria-labelledby") === underscoredTrigger.id
          );
        },
        null,
        timeout
      );
      await page.evaluate(() => {
        const state = window.__filesCompactContract.state;
        state.items = state.items.filter(item => (
          item.name !== "collision.a" && item.name !== "collision_a"
        ));
        state.totalItems -= 2;
      });
      await page.locator("#browseRefreshBtn").click();
      await waitForPageCondition(
        "Files compact fixture restored after ID collision contract",
        () => document.querySelectorAll("#serverFiles > .uploaded-file").length === 4,
        null,
        timeout
      );
    }

    await assertInlineDetailsIdContract();

    async function assertInlineDetailsContract() {
      const alphaEncodedPath = encodeURIComponent("/compact-contract/alpha.txt");
      const longEncodedPath = encodeURIComponent(`/compact-contract/${longName}`);
      const zetaEncodedPath = encodeURIComponent("/compact-contract/zeta.txt");
      const triggerSelector = encodedPath => (
        `#serverFiles [data-file-details-trigger][data-path="${encodedPath}"]`
      );
      const alphaTrigger = page.locator(triggerSelector(alphaEncodedPath));
      const longTrigger = page.locator(triggerSelector(longEncodedPath));
      const zetaTrigger = page.locator(triggerSelector(zetaEncodedPath));

      await page.evaluate(() => {
        const state = window.__filesCompactContract.state;
        state.detailRequests = [];
        state.pendingDetailPaths = { "/compact-contract/alpha.txt": true };
        state.pendingDetails = {};
        state.detailFailPaths = {};
      });

      const actionIsolation = await page.evaluate(([targetPath]) => {
        const trigger = document.querySelector(
          `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
        );
        const row = trigger?.closest(".uploaded-file");
        const checkbox = row?.querySelector("[data-file-select]");
        const more = row?.querySelector(".file-row__more");
        const moreSummary = more?.querySelector(":scope > summary");
        const beforeRequests = window.__filesCompactContract.state.detailRequests.length;
        if (checkbox) {
          checkbox.click();
        }
        const afterSelect = trigger?.getAttribute("aria-expanded") === "false";
        if (checkbox?.checked) {
          checkbox.click();
        }
        moreSummary?.click();
        const afterMore = Boolean(
          more?.open &&
          trigger?.getAttribute("aria-expanded") === "false" &&
          window.__filesCompactContract.state.detailRequests.length === beforeRequests
        );
        if (more) more.open = false;
        return {
          triggerOutsideActions: Boolean(
            trigger &&
            row?.contains(trigger) &&
            !trigger.contains(checkbox) &&
            !trigger.contains(row.querySelector(".file-row__actions"))
          ),
          removedInfoActionCount: Array.from(row?.querySelectorAll("[data-file-action]") || [])
            .filter(action => action.dataset.fileAction === "info").length,
          afterSelect,
          afterMore,
          requestCount: window.__filesCompactContract.state.detailRequests.length,
        };
      }, [alphaEncodedPath]);
      if (
        !actionIsolation.triggerOutsideActions ||
        actionIsolation.removedInfoActionCount !== 0 ||
        !actionIsolation.afterSelect ||
        !actionIsolation.afterMore ||
        actionIsolation.requestCount !== 0
      ) {
        throw new Error(`Files inline details action isolation failed: ${JSON.stringify(actionIsolation)}`);
      }

      await alphaTrigger.click();
      await waitForPageCondition(
        "Files inline details loading state",
        ([targetPath]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          const text = panel?.innerText || panel?.textContent || "";
          return Boolean(
            trigger?.getAttribute("aria-expanded") === "true" &&
            panel &&
            !panel.hidden &&
            panel.getAttribute("role") === "region" &&
            panel.getAttribute("aria-busy") === "true" &&
            text.includes("/compact-contract/alpha.txt")
          );
        },
        [alphaEncodedPath],
        timeout
      );

      await longTrigger.focus();
      await page.keyboard.press("Enter");
      await waitForPageCondition(
        "Files inline details Enter switches expanded row",
        ([stalePath, targetPath, targetName]) => {
          const staleTrigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${stalePath}"]`
          );
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          return Boolean(
            staleTrigger?.getAttribute("aria-expanded") === "false" &&
            trigger?.getAttribute("aria-expanded") === "true" &&
            trigger.getAttribute("aria-label")?.includes("Скрыть сведения") &&
            panel &&
            !panel.hidden &&
            panel.getAttribute("aria-labelledby") === trigger.id &&
            panel.getAttribute("aria-busy") === "false" &&
            (panel.innerText || panel.textContent || "").includes(targetName)
          );
        },
        [alphaEncodedPath, longEncodedPath, longName],
        timeout
      );
      await page.evaluate(() => {
        const state = window.__filesCompactContract.state;
        const release = state.pendingDetails["/compact-contract/alpha.txt"];
        delete state.pendingDetails["/compact-contract/alpha.txt"];
        delete state.pendingDetailPaths["/compact-contract/alpha.txt"];
        release();
      });
      await waitForPageCondition(
        "Files stale inline details response cannot repopulate switched row",
        ([stalePath, targetPath, targetName]) => {
          const staleTrigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${stalePath}"]`
          );
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          const stalePanel = staleTrigger?.getAttribute("aria-controls")
            ? document.getElementById(staleTrigger.getAttribute("aria-controls"))
            : null;
          const text = panel?.innerText || panel?.textContent || "";
          return Boolean(
            staleTrigger?.getAttribute("aria-expanded") === "false" &&
            stalePanel?.hidden &&
            trigger?.getAttribute("aria-expanded") === "true" &&
            panel &&
            !panel.hidden &&
            text.includes(targetName) &&
            !text.includes("alpha.txt")
          );
        },
        [alphaEncodedPath, longEncodedPath, longName],
        timeout
      );

      await page.keyboard.press("Space");
      await waitForPageCondition(
        "Files inline details Space repeat activation collapses",
        ([targetPath]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          return Boolean(
            document.activeElement === trigger &&
            trigger?.getAttribute("aria-expanded") === "false" &&
            panel?.hidden
          );
        },
        [longEncodedPath],
        timeout
      );

      const alphaRequestsBeforeSuccess = await page.evaluate(() => (
        window.__filesCompactContract.state.detailRequests
          .filter(request => request.pathname === "/compact-contract/alpha.txt").length
      ));
      await alphaTrigger.click();
      await waitForPageCondition(
        "Files inline details successful disclosure fields",
        ([targetPath, expectedRequests]) => {
          const state = window.__filesCompactContract.state;
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          const fields = Array.from(panel?.querySelectorAll(".file-row__details-field") || []);
          const labels = fields.map(field => field.querySelector("dt")?.textContent?.trim() || "");
          const values = Object.fromEntries(fields.map(field => [
            field.dataset.field,
            field.querySelector("dd")?.textContent?.trim() || "",
          ]));
          const requests = state.detailRequests
            .filter(request => request.pathname === "/compact-contract/alpha.txt");
          return Boolean(
            trigger?.getAttribute("aria-expanded") === "true" &&
            panel &&
            !panel.hidden &&
            panel.getAttribute("role") === "region" &&
            panel.getAttribute("aria-labelledby") === trigger.id &&
            panel.getAttribute("aria-busy") === "false" &&
            fields.length === 8 &&
            labels.includes("Имя файла") &&
            labels.includes("Источник MIME") &&
            labels.includes("Оценка содержимого") &&
            values["file-name"] === "alpha.txt" &&
            values["content-type"] === "application/pdf" &&
            values["mime-source"] === "по сигнатуре" &&
            values["content-assessment"] === "Формат распознан" &&
            requests.length === expectedRequests &&
            requests[requests.length - 1]?.search === "?inspect=true" &&
            !document.querySelector("#filesHttpErrorHost .http-error-card") &&
            !document.querySelector("#appDialog [role='dialog'], #appDialog [role='alertdialog']")
          );
        },
        [alphaEncodedPath, alphaRequestsBeforeSuccess + 1],
        timeout
      );
      await waitForLiveRegionText("filesResponseAreaLive", "Сведения о файле получены: alpha.txt", timeout);

      await alphaTrigger.click();
      await waitForPageCondition(
        "Files inline details collapses before cache check",
        ([targetPath]) => (
          document.querySelector(`#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`)
            ?.getAttribute("aria-expanded") === "false"
        ),
        [alphaEncodedPath],
        timeout
      );
      const detailRequestsBeforeCache = await page.evaluate(() => (
        window.__filesCompactContract.state.detailRequests.length
      ));
      await alphaTrigger.click();
      await waitForPageCondition(
        "Files inline details cached reopen avoids INFO",
        ([targetPath, beforeRequests]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          return Boolean(
            trigger?.getAttribute("aria-expanded") === "true" &&
            panel &&
            !panel.hidden &&
            (panel.innerText || panel.textContent || "").includes("alpha.txt") &&
            window.__filesCompactContract.state.detailRequests.length === beforeRequests
          );
        },
        [alphaEncodedPath, detailRequestsBeforeCache],
        timeout
      );

      await alphaTrigger.focus();
      await page.keyboard.press("Escape");
      await waitForPageCondition(
        "Files inline details Escape collapses and restores focus",
        ([targetPath]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          return Boolean(
            document.activeElement === trigger &&
            trigger?.getAttribute("aria-expanded") === "false" &&
            trigger.getAttribute("aria-label")?.includes("Показать сведения") &&
            panel?.hidden
          );
        },
        [alphaEncodedPath],
        timeout
      );

      await alphaTrigger.click();
      await waitForPageCondition(
        "Files inline details cached expansion before refresh",
        ([targetPath]) => (
          document.querySelector(`#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`)
            ?.getAttribute("aria-expanded") === "true"
        ),
        [alphaEncodedPath],
        timeout
      );
      await page.locator("#browseRefreshBtn").click();
      await waitForPageCondition(
        "Files refresh clears expanded inline details",
        ([targetPath]) => Boolean(
          document.getElementById("serverFiles")?.getAttribute("aria-busy") === "false" &&
          document.querySelector(`#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`)
            ?.getAttribute("aria-expanded") === "false" &&
          !Array.from(document.querySelectorAll("#serverFiles .file-row__details-panel"))
            .some(panel => !panel.hidden)
        ),
        [alphaEncodedPath],
        timeout
      );
      const detailRequestsBeforeRefreshReopen = await page.evaluate(() => (
        window.__filesCompactContract.state.detailRequests.length
      ));
      await page.locator(triggerSelector(alphaEncodedPath)).click();
      await waitForPageCondition(
        "Files refresh invalidates inline details cache",
        ([targetPath, beforeRequests]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          return Boolean(
            trigger?.getAttribute("aria-expanded") === "true" &&
            panel &&
            !panel.hidden &&
            (panel.innerText || panel.textContent || "").includes("alpha.txt") &&
            window.__filesCompactContract.state.detailRequests.length === beforeRequests + 1
          );
        },
        [alphaEncodedPath, detailRequestsBeforeRefreshReopen],
        timeout
      );

      const detailRequestsBeforeLocale = await page.evaluate(() => (
        window.__filesCompactContract.state.detailRequests.length
      ));
      await switchLanguage("en");
      await waitForPageCondition(
        "Files locale relocalizes cached inline details without request",
        ([targetPath, beforeRequests]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          const text = panel?.innerText || panel?.textContent || "";
          return Boolean(
            trigger?.getAttribute("aria-expanded") === "true" &&
            trigger.getAttribute("aria-label")?.includes("Hide file details") &&
            panel &&
            !panel.hidden &&
            text.includes("File name") &&
            text.includes("MIME source") &&
            text.includes("Content assessment") &&
            text.includes("signature") &&
            text.includes("Format recognized") &&
            window.__filesCompactContract.state.detailRequests.length === beforeRequests
          );
        },
        [alphaEncodedPath, detailRequestsBeforeLocale],
        timeout
      );

      await page.evaluate(() => document.documentElement.setAttribute("data-theme", "light"));
      await page.screenshot({
        path: `${artifactDir}/files-details-inline-desktop-light-en.png`,
        fullPage: true,
      });
      await page.setViewportSize({ width: 390, height: 844 });
      const mobileExpanded = await page.evaluate(([targetPath]) => {
        const trigger = document.querySelector(
          `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
        );
        const row = trigger?.closest(".uploaded-file");
        const panel = trigger?.getAttribute("aria-controls")
          ? document.getElementById(trigger.getAttribute("aria-controls"))
          : null;
        const fields = Array.from(panel?.querySelectorAll(".file-row__details-field") || []);
        return {
          triggerHeight: trigger?.getBoundingClientRect().height || 0,
          fieldCount: fields.length,
          panelColumns: panel ? getComputedStyle(panel).gridTemplateColumns : "",
          fieldColumns: fields.map(field => getComputedStyle(field).gridTemplateColumns),
          rowOverflow: Boolean(row && row.scrollWidth > row.clientWidth + 1),
          panelOverflow: Boolean(panel && panel.scrollWidth > panel.clientWidth + 1),
          documentOverflow: document.documentElement.scrollWidth > innerWidth + 1,
        };
      }, [alphaEncodedPath]);
      if (
        mobileExpanded.triggerHeight < 44 ||
        mobileExpanded.fieldCount !== 8 ||
        mobileExpanded.rowOverflow ||
        mobileExpanded.panelOverflow ||
        mobileExpanded.documentOverflow
      ) {
        throw new Error(`Files inline details mobile layout failed: ${JSON.stringify(mobileExpanded)}`);
      }
      await page.screenshot({
        path: `${artifactDir}/files-details-inline-mobile-light-en.png`,
        fullPage: true,
      });
      await page.setViewportSize({ width: 1440, height: 1024 });
      await switchLanguage("ru");
      await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
      await page.locator(triggerSelector(alphaEncodedPath)).click();
      await waitForPageCondition(
        "Files inline details collapsed before legacy retry",
        ([targetPath]) => (
          document.querySelector(`#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`)
            ?.getAttribute("aria-expanded") === "false"
        ),
        [alphaEncodedPath],
        timeout
      );

      await page.evaluate(() => {
        window.__filesCompactContract.state.detailFailPaths["/compact-contract/zeta.txt"] = true;
      });
      const zetaRequestsBefore = await page.evaluate(() => (
        window.__filesCompactContract.state.detailRequests
          .filter(request => request.pathname === "/compact-contract/zeta.txt").length
      ));
      await zetaTrigger.click();
      await waitForPageCondition(
        "Files inline details error state with Retry",
        ([targetPath, beforeRequests]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          const retry = panel?.querySelector("[data-file-details-retry]");
          const requests = window.__filesCompactContract.state.detailRequests
            .filter(request => request.pathname === "/compact-contract/zeta.txt");
          return Boolean(
            trigger?.getAttribute("aria-expanded") === "true" &&
            panel &&
            !panel.hidden &&
            panel.getAttribute("aria-busy") === "false" &&
            panel.textContent.includes("Не удалось получить сведения о файле") &&
            retry &&
            retry.textContent.trim() === "Повторить" &&
            requests.length === beforeRequests + 1 &&
            requests[requests.length - 1]?.search === "?inspect=true"
          );
        },
        [zetaEncodedPath, zetaRequestsBefore],
        timeout
      );
      await waitForLiveRegionText("filesResponseAreaLive", "Не удалось получить сведения о файле", timeout);
      await page.evaluate(() => {
        delete window.__filesCompactContract.state.detailFailPaths["/compact-contract/zeta.txt"];
      });
      await page.locator(`#serverFiles [data-file-details-retry][data-path="${zetaEncodedPath}"]`).click();
      await waitForPageCondition(
        "Files inline details Retry renders legacy INFO fields",
        ([targetPath, beforeRequests]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          const fields = Array.from(panel?.querySelectorAll(".file-row__details-field") || []);
          const values = Object.fromEntries(fields.map(field => [
            field.dataset.field,
            field.querySelector("dd")?.textContent?.trim() || "",
          ]));
          const requests = window.__filesCompactContract.state.detailRequests
            .filter(request => request.pathname === "/compact-contract/zeta.txt");
          return Boolean(
            trigger?.getAttribute("aria-expanded") === "true" &&
            panel &&
            !panel.hidden &&
            panel.getAttribute("aria-busy") === "false" &&
            fields.length === 8 &&
            values["file-name"] === "zeta.txt" &&
            values["content-type"] === "text/plain" &&
            values["mime-source"] === "-" &&
            values["content-assessment"] === "-" &&
            requests.length === beforeRequests + 2
          );
        },
        [zetaEncodedPath, zetaRequestsBefore],
        timeout
      );
      const retryFocusRestored = await page.evaluate(([targetPath]) => {
        const trigger = document.querySelector(
          `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
        );
        return document.activeElement === trigger;
      }, [zetaEncodedPath]);
      if (!retryFocusRestored) {
        throw new Error("Files inline details Retry did not restore focus to the row trigger");
      }
      const legacyContract = await page.evaluate(([targetPath, beforeRequests]) => {
        const trigger = document.querySelector(
          `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
        );
        const panel = trigger?.getAttribute("aria-controls")
          ? document.getElementById(trigger.getAttribute("aria-controls"))
          : null;
        const fields = Array.from(panel?.querySelectorAll(".file-row__details-field") || []);
        const values = Object.fromEntries(fields.map(field => [
          field.dataset.field,
          field.querySelector("dd")?.textContent?.trim() || "",
        ]));
        const requests = window.__filesCompactContract.state.detailRequests
          .filter(request => request.pathname === "/compact-contract/zeta.txt");
        return {
          expanded: trigger?.getAttribute("aria-expanded") || "",
          hidden: Boolean(panel?.hidden),
          busy: panel?.getAttribute("aria-busy") || "",
          fieldCount: fields.length,
          values,
          requestCount: requests.length,
          expectedRequestCount: beforeRequests + 2,
          latestSearch: requests[requests.length - 1]?.search || "",
          hasDialog: Boolean(document.querySelector("#appDialog [role='dialog'], #appDialog [role='alertdialog']")),
          hasFilesErrorCard: Boolean(document.querySelector("#filesHttpErrorHost .http-error-card")),
        };
      }, [zetaEncodedPath, zetaRequestsBefore]);
      if (
        legacyContract.expanded !== "true" ||
        legacyContract.hidden ||
        legacyContract.busy !== "false" ||
        legacyContract.fieldCount !== 8 ||
        legacyContract.values["file-name"] !== "zeta.txt" ||
        legacyContract.values["content-type"] !== "text/plain" ||
        legacyContract.values["mime-source"] !== "-" ||
        legacyContract.values["content-assessment"] !== "-" ||
        legacyContract.requestCount !== legacyContract.expectedRequestCount ||
        legacyContract.latestSearch !== "?inspect=true" ||
        legacyContract.hasDialog ||
        legacyContract.hasFilesErrorCard
      ) {
        throw new Error(`Files legacy inline details fallback failed: ${JSON.stringify(legacyContract)}`);
      }
      await page.locator(triggerSelector(zetaEncodedPath)).click();
      return {
        actionIsolation,
        mobileExpanded,
        detailRequests: await page.evaluate(() => (
          window.__filesCompactContract.state.detailRequests.slice()
        )),
        screenshots: [
          "files-details-inline-desktop-light-en.png",
          "files-details-inline-mobile-light-en.png",
        ],
      };
    }

    const inlineDetails = await assertInlineDetailsContract();

    async function assertFileOverflowMenuContract(width, lang, theme) {
      const expected = lang === "ru"
        ? {
            trigger: "Дополнительные действия",
            actions: [
              ["decrypt-xor", "Скачать с XOR-расшифровкой"],
              ["smuggle", "HTML Smuggling"],
              ["delete", "Удалить файл"],
            ],
            xorHint: "Формат не распознан: пробуйте, только если использовался XOR.",
          }
        : {
            trigger: "More actions",
            actions: [
              ["decrypt-xor", "Download with XOR decryption"],
              ["smuggle", "HTML smuggling"],
              ["delete", "Delete file"],
            ],
            xorHint: "Format not recognized; try only if XOR was used",
          };
      const menu = await page.evaluate(([fixtureLongName, expectedCopy, compact]) => {
        const list = document.getElementById("serverFiles");
        const row = Array.from(list?.querySelectorAll(".uploaded-file--file") || [])
          .find(candidate => candidate.querySelector(".file-name")?.textContent === fixtureLongName);
        const details = row?.querySelector(".file-row__more");
        const summary = details?.querySelector(":scope > summary");
        const panel = details?.querySelector(":scope > .file-row__actions-secondary");
        const download = row?.querySelector('[data-file-action="download"]');
        if (!row || !details || !summary || !panel || !download) {
          throw new Error("Files overflow fixture is incomplete");
        }
        details.open = true;
        const rect = element => {
          const box = element.getBoundingClientRect();
          return {
            left: box.left,
            right: box.right,
            top: box.top,
            bottom: box.bottom,
            width: box.width,
            height: box.height,
          };
        };
        const actions = Array.from(panel.querySelectorAll("[data-file-action]")).map(button => ({
          action: button.dataset.fileAction,
          text: button.textContent.trim(),
          rect: rect(button),
        }));
        const neutralAction = panel.querySelector('[data-file-action="smuggle"]');
        const xorAction = panel.querySelector('[data-file-action="decrypt-xor"]');
        const xorHint = panel.querySelector(".file-row__xor-hint");
        const deleteAction = panel.querySelector('[data-file-action="delete"]');
        const resolveDangerStyle = property => {
          const probe = document.createElement("span");
          probe.style.setProperty(property, "var(--accent-danger)");
          document.body.appendChild(probe);
          const value = getComputedStyle(probe).getPropertyValue(property);
          probe.remove();
          return value;
        };
        const separator = panel.querySelector(".file-row__menu-separator");
        return {
          triggerText: summary.textContent.trim(),
          triggerName: summary.getAttribute("aria-label") || "",
          triggerRect: rect(summary),
          panelRect: rect(panel),
          actions,
          separator: separator ? {
            semantic: separator.getAttribute("role") === "separator" || separator.tagName === "HR",
            rect: rect(separator),
          } : null,
          downloadRect: rect(download),
          actionsRect: rect(row.querySelector(".file-row__actions")),
          rowRect: rect(row),
          panelPosition: getComputedStyle(panel).position,
          panelColumns: getComputedStyle(panel).gridTemplateColumns.trim().split(/\s+/).filter(Boolean).length,
          neutralStyle: neutralAction ? {
            color: getComputedStyle(neutralAction).color,
            borderColor: getComputedStyle(neutralAction).borderColor,
          } : null,
          xorAction: xorAction ? {
            describedBy: xorAction.getAttribute("aria-describedby") || "",
            caution: xorAction.classList.contains("file-row__action-xor--caution"),
            color: getComputedStyle(xorAction).color,
            borderColor: getComputedStyle(xorAction).borderColor,
          } : null,
          xorHint: xorHint ? {
            id: xorHint.id,
            text: xorHint.textContent.trim(),
            rect: rect(xorHint),
          } : null,
          deleteStyle: deleteAction ? {
            color: getComputedStyle(deleteAction).color,
            borderColor: getComputedStyle(deleteAction).borderColor,
          } : null,
          accentDangerStyle: {
            color: resolveDangerStyle("color"),
            borderColor: resolveDangerStyle("border-color"),
          },
          listOverflow: list.scrollWidth > list.clientWidth + 1,
          rowOverflow: row.scrollWidth > row.clientWidth + 1,
          documentOverflow: document.documentElement.scrollWidth > innerWidth + 1,
          removedInfoActionCount: Array.from(panel.querySelectorAll("[data-file-action]"))
            .filter(action => action.dataset.fileAction === "info").length,
          compact,
          expectedCopy,
        };
      }, [longName, expected, width <= 640]);

      const actionOrder = menu.actions.map(item => item.action).join(",");
      const expectedOrder = expected.actions.map(([action]) => action).join(",");
      const exactCopy = menu.actions.every((item, index) => item.text === expected.actions[index]?.[1]);
      const vertical = menu.actions.every((item, index) => index === 0 ||
        item.rect.top >= menu.actions[index - 1].rect.bottom - 1);
      const fullWidthItems = menu.actions.every(item =>
        item.rect.height >= 44 &&
        item.rect.left >= menu.panelRect.left - 1 &&
        item.rect.right <= menu.panelRect.right + 1 &&
        Math.abs(item.rect.width - menu.actions[0].rect.width) <= 1
      );
      const triggerSquare =
        menu.triggerRect.width >= 43 && menu.triggerRect.width <= 45 &&
        menu.triggerRect.height >= 43 && menu.triggerRect.height <= 45;
      const desktopBounds =
        menu.panelRect.width >= 279 && menu.panelRect.width <= 281 &&
        menu.panelRect.left >= -1 && menu.panelRect.right <= width + 1 &&
        menu.panelPosition === "absolute" && menu.panelColumns === 1;
      const mobileBounds =
        menu.panelRect.left >= menu.actionsRect.left - 1 &&
        menu.panelRect.right <= menu.actionsRect.right + 1 &&
        Math.abs(menu.panelRect.width - menu.actionsRect.width) <= 1 &&
        menu.panelRect.top >= menu.downloadRect.bottom - 1 &&
        Math.abs(menu.downloadRect.top - menu.triggerRect.top) <= 1 &&
        menu.panelPosition === "absolute" && menu.panelColumns === 1;
      const dangerStyle = Boolean(
        menu.neutralStyle && menu.deleteStyle && menu.accentDangerStyle &&
        menu.deleteStyle.color === menu.accentDangerStyle.color &&
        menu.deleteStyle.borderColor === menu.accentDangerStyle.borderColor &&
        (
          menu.deleteStyle.color !== menu.neutralStyle.color ||
          menu.deleteStyle.borderColor !== menu.neutralStyle.borderColor
        )
      );
      const cautionStyle = Boolean(
        menu.neutralStyle && menu.xorAction &&
        (
          menu.xorAction.color !== menu.neutralStyle.color ||
          menu.xorAction.borderColor !== menu.neutralStyle.borderColor
        )
      );
      const valid =
        menu.triggerText === "⋮" &&
        menu.triggerName === `${expected.trigger}: ${longName}` &&
        menu.removedInfoActionCount === 0 &&
        actionOrder === expectedOrder && exactCopy && vertical && fullWidthItems &&
        menu.xorAction?.caution &&
        menu.xorAction.describedBy === menu.xorHint?.id &&
        menu.xorHint?.text === expected.xorHint &&
        menu.xorHint.rect.left >= menu.panelRect.left - 1 &&
        menu.xorHint.rect.right <= menu.panelRect.right + 1 &&
        menu.separator?.semantic &&
        menu.separator.rect.top >= menu.actions[1].rect.bottom - 1 &&
        menu.separator.rect.bottom <= menu.actions[2].rect.top + 1 &&
        triggerSquare &&
        (width <= 640 ? mobileBounds : desktopBounds) &&
        dangerStyle && (!menu.compact || cautionStyle) &&
        !menu.listOverflow && !menu.rowOverflow && !menu.documentOverflow;
      if (!valid) {
        throw new Error(
          `Files overflow menu contract failed (${width}/${lang}/${theme}): ${JSON.stringify(menu)}`
        );
      }
      await page.screenshot({
        path: `${artifactDir}/files-overflow-${width <= 640 ? "mobile" : "desktop"}-${lang}-${theme}.png`,
        fullPage: true,
      });
      await page.evaluate(() => {
        const details = document.querySelector("#serverFiles .file-row__more[open]");
        if (details) details.open = false;
      });
      return menu;
    }

    const responsiveStates = [];
    for (const width of [1440, 390]) {
      for (const lang of ["ru", "en"]) {
        for (const theme of ["dark", "light"]) {
          await page.setViewportSize({ width, height: width === 390 ? 844 : 1024 });
          await switchLanguage(lang);
          await page.evaluate((targetTheme) => {
            document.documentElement.setAttribute("data-theme", targetTheme);
          }, theme);
          const layout = await page.evaluate(([fixtureLongName]) => {
            const list = document.getElementById("serverFiles");
            const toolbar = document.querySelector(".file-browser__toolbar");
            const toolbarControls = [
              document.getElementById("browseRootBtn"),
              document.getElementById("browseUpBtn"),
              document.querySelector(".file-browser__path"),
              document.getElementById("browseBtn"),
              document.getElementById("browseRefreshBtn"),
            ];
            const toolbarRects = toolbarControls.map(control => control?.getBoundingClientRect());
            const toolbarColumns = getComputedStyle(toolbar).gridTemplateColumns
              .trim().split(/\s+/).filter(Boolean).length;
            const row = Array.from(list.querySelectorAll(".uploaded-file--file"))
              .find(candidate => candidate.querySelector(".file-name")?.textContent === fixtureLongName);
            const name = row?.querySelector(".file-name");
            const rowRect = row?.getBoundingClientRect();
            const nameRect = name?.getBoundingClientRect();
            const targets = Array.from(
              list.querySelectorAll(
                ".file-select, .file-row__details-trigger, .file-row__more > summary, .file-row__action-main"
              )
            ).map(element => {
              const rect = element.getBoundingClientRect();
              return { width: rect.width, height: rect.height };
            });
            return {
              documentOverflow: document.documentElement.scrollWidth > innerWidth + 1,
              listOverflow: list.scrollWidth > list.clientWidth + 1,
              rowOverflow: Boolean(row && row.scrollWidth > row.clientWidth + 1),
              longNameInside: Boolean(
                rowRect && nameRect &&
                nameRect.left >= rowRect.left - 1 &&
                nameRect.right <= rowRect.right + 1
              ),
              toolbarColumns,
              toolbarOneRow: toolbarRects.every(Boolean) && (
                Math.max(...toolbarRects.map(rect => rect.top)) -
                Math.min(...toolbarRects.map(rect => rect.top)) <= 1
              ),
              targets,
            };
          }, [longName]);
          if (
            layout.documentOverflow ||
            layout.listOverflow ||
            layout.rowOverflow ||
            !layout.longNameInside ||
            (
              width === 1440 && lang === "en" && theme === "light" &&
              (layout.toolbarColumns !== 5 || !layout.toolbarOneRow)
            ) ||
            layout.targets.some(target => target.width < 44 || target.height < 44)
          ) {
            throw new Error(
              `Files responsive overflow/target contract failed (${width}/${lang}/${theme}): ${JSON.stringify(layout)}`
            );
          }
          const overflowMenu = await assertFileOverflowMenuContract(width, lang, theme);
          responsiveStates.push({ width, lang, theme, ...layout, overflowMenu });
          if (lang === "en" && theme === "light") {
            await page.screenshot({
              path: `${artifactDir}/files-compact-${width === 390 ? "mobile" : "desktop"}-light-en.png`,
              fullPage: true,
            });
          }
        }
      }
    }
    await page.setViewportSize({ width: 1440, height: 1024 });
    await switchLanguage("ru");
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));

    const callsBeforePendingLocale = await page.evaluate(() => {
      const contract = window.__filesCompactContract;
      contract.state.pendingRelease = true;
      return contract.state.infoCalls;
    });
    await page.locator("#browseRefreshBtn").click();
    await waitForPageCondition(
      "Files delayed refresh enters authoritative loading phase",
      ([expectedCalls]) => {
        const list = document.getElementById("serverFiles");
        const status = document.getElementById("filesBrowseStatus");
        return Boolean(
          list?.getAttribute("aria-busy") === "true" &&
          list.dataset.browsePhase === "loading" &&
          status?.dataset.browsePhase === "loading" &&
          window.__filesCompactContract.state.infoCalls === expectedCalls + 1
        );
      },
      [callsBeforePendingLocale],
      timeout
    );
    await switchLanguage("en");
    await waitForPageCondition(
      "Files locale change preserves pending browse loading phase",
      ([expectedCalls]) => {
        const list = document.getElementById("serverFiles");
        const status = document.getElementById("filesBrowseStatus");
        const loadingMessage = list?.querySelector(
          ':scope > [role="listitem"][data-browse-phase="loading"]'
        );
        return Boolean(
          list?.getAttribute("aria-busy") === "true" &&
          list.dataset.browsePhase === "loading" &&
          status?.dataset.browsePhase === "loading" &&
          status.textContent.includes("/compact-contract") &&
          loadingMessage?.textContent.includes("/compact-contract") &&
          !list.querySelector(".uploaded-file") &&
          window.__filesCompactContract.state.infoCalls === expectedCalls + 1
        );
      },
      [callsBeforePendingLocale],
      timeout
    );
    await page.evaluate(() => {
      const contract = window.__filesCompactContract;
      const release = contract.state.pendingRelease;
      contract.state.pendingRelease = false;
      release(new Response(JSON.stringify({
        entry: { kind: "directory", path: "/compact-contract" },
        page: { total_items: 10 },
        contents: [
          ...contract.state.items,
          { name: "locale-current.txt", kind: "file" },
        ],
      }), {
        status: 200,
        statusText: "OK",
        headers: { "Content-Type": "application/json" },
      }));
    });
    await waitForPageCondition(
      "Files delayed response wins after locale change",
      ([expectedCalls]) => {
        const list = document.getElementById("serverFiles");
        const status = document.getElementById("filesBrowseStatus");
        return Boolean(
          list?.getAttribute("aria-busy") === "false" &&
          list.dataset.browsePhase === "complete" &&
          status?.dataset.browsePhase === "complete" &&
          status.textContent.includes("Showing 5 of 10") &&
          Array.from(list.querySelectorAll(".file-name"))
            .some(name => name.textContent === "locale-current.txt") &&
          window.__filesCompactContract.state.infoCalls === expectedCalls + 1
        );
      },
      [callsBeforePendingLocale],
      timeout
    );
    await switchLanguage("ru");

    const alphaPath = encodeURIComponent("/compact-contract/alpha.txt");
    const zetaPath = encodeURIComponent("/compact-contract/zeta.txt");
    await page.locator(`[data-file-select][data-path="${alphaPath}"]`).check();
    await waitForPageCondition(
      "Files selection bar is contextual",
      () => {
        const bar = document.getElementById("filesSelectionBar");
        const button = document.getElementById("deleteSelectedUploadsBtn");
        return Boolean(!bar?.hidden && bar.textContent.includes("Выбрано: 1") && !button?.disabled);
      }
    );
    const callsBeforeSelectedLocale = await page.evaluate(
      () => window.__filesCompactContract.state.infoCalls
    );
    await switchLanguage("en");
    await waitForPageCondition(
      "Files locale rerender preserves visible selected file state",
      ([encodedAlphaPath, expectedCalls]) => {
        const selectBox = document.querySelector(
          `#serverFiles [data-file-select][data-path="${encodedAlphaPath}"]`
        );
        const row = selectBox?.closest(".uploaded-file");
        const bar = document.getElementById("filesSelectionBar");
        const deleteButton = document.getElementById("deleteSelectedUploadsBtn");
        const clearButton = document.getElementById("clearSelectedUploadsBtn");
        return Boolean(
          selectBox?.checked &&
          row?.classList.contains("is-selected") &&
          !bar?.hidden &&
          bar.textContent.includes("Selected: 1") &&
          !deleteButton?.disabled &&
          !clearButton?.disabled &&
          window.__filesCompactContract.state.infoCalls === expectedCalls
        );
      },
      [alphaPath, callsBeforeSelectedLocale],
      timeout
    );
    await switchLanguage("ru");
    await page.locator("#clearSelectedUploadsBtn").click();
    await waitForPageCondition(
      "Files clear selection hides contextual bar",
      () => document.getElementById("filesSelectionBar")?.hidden === true
    );

    await page.locator(`[data-file-select][data-path="${alphaPath}"]`).check();
    await page.locator(`[data-file-select][data-path="${zetaPath}"]`).check();
    await page.locator("#deleteSelectedUploadsBtn").click();
    await page.locator('#appDialog [data-dialog-action="cancel"]').click();
    await waitForPageCondition(
      "Files bulk delete cancellation restores focus and selection",
      () => Boolean(
        !document.getElementById("appDialog") &&
        document.activeElement?.id === "deleteSelectedUploadsBtn" &&
        document.querySelectorAll("#serverFiles [data-file-select]:checked").length === 2
      )
    );
    await page.locator("#deleteSelectedUploadsBtn").click();
    await confirmAppDialog(/alpha\.txt|zeta\.txt/, timeout);
    await waitForPageCondition(
      "Files bulk delete refreshes list and clears selection",
      ([alpha, zeta]) => Boolean(
        !document.querySelector(`#serverFiles [data-path="${alpha}"]`) &&
        !document.querySelector(`#serverFiles [data-path="${zeta}"]`) &&
        document.getElementById("filesSelectionBar")?.hidden === true
      ),
      [alphaPath, zetaPath],
      timeout
    );

    const callsBeforeLocale = await page.evaluate(() => window.__filesCompactContract.state.infoCalls);
    await switchLanguage("en");
    await waitForPageCondition(
      "Files locale rerenders without request",
      ([expectedCalls]) => Boolean(
        document.getElementById("filesBrowseStatus")?.textContent.includes("Showing 2 of 9") &&
        Array.from(document.querySelectorAll(".file-row__more > summary"))
          .every(summary => summary.textContent.trim() === "⋮") &&
        window.__filesCompactContract.state.infoCalls === expectedCalls
      ),
      [callsBeforeLocale]
    );
    await switchLanguage("ru");

    await page.evaluate(() => {
      const contract = window.__filesCompactContract;
      contract.state.items.push({ name: "refresh.txt", kind: "file" });
    });
    const callsBeforeRefresh = await page.evaluate(() => window.__filesCompactContract.state.infoCalls);
    await page.locator("#browseRefreshBtn").click();
    await waitForPageCondition(
      "Files toolbar Refresh performs a new browse",
      ([beforeCalls]) => Boolean(
        Array.from(document.querySelectorAll("#serverFiles .file-name"))
          .some(name => name.textContent === "refresh.txt") &&
        window.__filesCompactContract.state.infoCalls === beforeCalls + 1 &&
        document.querySelector('[data-tool-summary-scope="files"]')?.dataset.phase === "empty"
      ),
      [callsBeforeRefresh],
      timeout
    );

    const dangerContrast = await page.evaluate(() => {
      document.documentElement.setAttribute("data-theme", "dark");
      const details = document.querySelector("#serverFiles .file-row__more");
      details.open = true;
      const danger = details.querySelector(".file-row__action-danger");
      const style = getComputedStyle(danger);
      const backgroundStyle = getComputedStyle(
        details.querySelector(".file-row__actions-secondary")
      );
      const parse = value => (value.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
      const luminance = rgb => {
        const channels = rgb.map(value => {
          const normalized = value / 255;
          return normalized <= 0.03928
            ? normalized / 12.92
            : ((normalized + 0.055) / 1.055) ** 2.4;
        });
        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
      };
      const foreground = luminance(parse(style.color));
      const background = luminance(parse(backgroundStyle.backgroundColor));
      const ratio = (Math.max(foreground, background) + 0.05)
        / (Math.min(foreground, background) + 0.05);
      return { ratio, color: style.color, background: backgroundStyle.backgroundColor };
    });
    if (dangerContrast.ratio < 4.5) {
      throw new Error(`Files dark danger contrast below 4.5:1: ${JSON.stringify(dangerContrast)}`);
    }
    await page.screenshot({
      path: `${artifactDir}/files-compact-desktop-dark-ru.png`,
      fullPage: true,
    });

    await page.evaluate(() => {
      const contract = window.__filesCompactContract;
      contract.state.fail = true;
      window.__filesCompactHostileExecuted = false;
    });
    await page.locator("#browseRefreshBtn").click();
    await waitForPageCondition(
      "Files stale cached list disables actions and renders hostile text safely",
      () => {
        const list = document.getElementById("serverFiles");
        const card = document.querySelector("#filesHttpErrorHost .http-error-card");
        const controls = Array.from(list?.querySelectorAll("button, input") || []);
        return Boolean(
          list?.dataset.stale === "true" &&
          controls.length > 0 && controls.every(control => control.disabled) &&
          card?.textContent.includes("<img src=x") &&
          !card.querySelector("img") &&
          !window.__filesCompactHostileExecuted
        );
      },
      null,
      timeout
    );
    await page.evaluate(() => {
      window.__filesCompactContract.state.fail = false;
    });
    await page.locator('#filesHttpErrorHost [data-http-error-action="retry"]').click();
    await waitForPageCondition(
      "Files Retry restores a fresh enabled list",
      () => Boolean(
        document.getElementById("serverFiles")?.dataset.stale === "false" &&
        !document.querySelector("#filesHttpErrorHost .http-error-card") &&
        Array.from(document.querySelectorAll("#serverFiles button, #serverFiles input"))
          .some(control => !control.disabled)
      ),
      null,
      timeout
    );

    await page.evaluate(() => {
      const contract = window.__filesCompactContract;
      contract.state.items = [];
      contract.state.totalItems = 0;
    });
    await page.locator("#browseRefreshBtn").click();
    await waitForPageCondition(
      "Files empty state stays inside semantic list",
      () => Boolean(
        document.querySelector('#serverFiles[role="list"] > [role="listitem"][data-browse-phase="empty"]') &&
        document.getElementById("serverFiles")?.getAttribute("aria-busy") === "false"
      ),
      null,
      timeout
    );

    const result = await page.evaluate(() => {
      const contract = window.__filesCompactContract;
      return {
        infoCalls: contract.state.infoCalls,
        deleteCalls: contract.state.deleteCalls.slice(),
      };
    });
    return {
      ...result,
      longName,
      dangerContrast,
      inlineDetails,
      responsiveStates,
      screenshots: [
        ...inlineDetails.screenshots,
        "files-compact-desktop-dark-ru.png",
        "files-compact-desktop-light-en.png",
        "files-compact-mobile-light-en.png",
      ],
    };
    } catch (error) {
      contractFailure = error;
      throw error;
    } finally {
      try {
        await page.evaluate(() => {
          const contract = window.__filesCompactContract;
          if (contract) {
            for (const key of ["initialRelease", "pendingRelease"]) {
              const release = contract.state[key];
              if (typeof release === "function") {
                contract.state[key] = false;
                release(new Response("", {
                  status: 499,
                  statusText: "Controlled contract cleanup",
                }));
              }
            }
            window.XferryApp.service("http")["set-adapter"](contract.originalAdapter);
          }
          delete window.__filesCompactContract;
          delete window.__filesCompactInitialBrowse;
          delete window.__filesCompactHostileExecuted;
          document.documentElement.setAttribute("data-theme", "dark");
        });
        await page.locator("#tab-upload").click();
        await waitForTabState("upload", { focused: true });
      } catch (cleanupError) {
        if (!contractFailure) {
          throw cleanupError;
        }
        contractFailure.message += `\nFiles compact cleanup also failed: ${cleanupError.message}`;
      }
    }
  }

  async function assertVisibleAppVersion(timeout = 10000) {
    const version = await page.evaluate(async () => {
      const response = await fetch("/", { method: "PING" });
      const info = await response.json();
      const match = String(info.server || "").match(/^XFerry\/(.+)$/);
      if (!match) {
        throw new Error(`PING server label missing version: ${JSON.stringify(info)}`);
      }
      return match[1];
    });

    await page.evaluate(async () => {
      const versionEl = document.getElementById("appVersion");
      const core = window.XferryApp?.service("core");
      if (!versionEl || !core || typeof core.checkServer !== "function") {
        throw new Error("Runtime version update contract is unavailable");
      }
      versionEl.textContent = "v0.0.0-stale";
      versionEl.dataset.appVersion = "0.0.0-stale";
      await core.checkServer();
    });

    await waitForPageCondition(
      `visible app version (${version})`,
      ([expectedVersion]) => {
        const versionEl = document.getElementById("appVersion");
        return Boolean(
          versionEl &&
          versionEl.dataset.appVersion === expectedVersion &&
          versionEl.textContent.trim() === `v${expectedVersion}`
        );
      },
      [version],
      timeout
    );
  }

  async function waitForAdvancedUploadReady(timeout = 10000) {
    await waitForPageCondition(
      "waitForAdvancedUploadReady",
      () => {
        const tab = document.getElementById("tab-opsec");
        const panel = document.getElementById("opsec-tab");
        const fileInput = document.getElementById("opsecFileInput");
        const uploadBtn = document.getElementById("opsecUploadBtn");
        const dropZone = document.getElementById("opsecDropZone");
        const controls = [
          document.getElementById("opsecMethodInput"),
          document.getElementById("opsecRandomMethodBtn"),
          document.getElementById("opsecEncryptionSelect"),
          document.getElementById("opsecConstructorMode"),
          document.getElementById("opsecProfileSelect"),
          document.getElementById("opsecCarrierSelect"),
          document.getElementById("opsecBodyFormatSelect"),
          document.getElementById("opsecEncodingSelect"),
          document.getElementById("opsecFilenamePrimarySelect"),
        ];

        return Boolean(
          tab &&
          !tab.hidden &&
          !tab.disabled &&
          panel &&
          fileInput &&
          !fileInput.disabled &&
          fileInput.tabIndex === -1 &&
          uploadBtn &&
          uploadBtn.disabled === true &&
          controls.every((control) => control && control.disabled === false) &&
          dropZone &&
          dropZone.getAttribute("aria-disabled") === "false" &&
          dropZone.tabIndex === 0
        );
      },
      null,
      timeout
    );
  }

  async function waitForAdvancedSessionReady(timeout = 10000) {
    await waitForPageCondition(
      "waitForAdvancedSessionReady",
      () => {
        const service = window.XferryApp?.service("advanced-session");
        const snapshot = service?.getSnapshot();
        const status = document.getElementById("advancedSessionStatus");
        return Boolean(
          service &&
          snapshot &&
          snapshot.active === true &&
          snapshot.phase === "active" &&
          document.getElementById("advancedSessionPanel")?.dataset.sessionPhase === "active" &&
          status &&
          status.getAttribute("role") === "status" &&
          status.getAttribute("aria-live") === "polite" &&
          status.getAttribute("aria-atomic") === "true"
        );
      },
      null,
      timeout
    );
  }

  async function assertHomeToolEntryState(expectedTabs, timeout = 10000) {
    await waitForPageCondition(
      `home tool entry state (${expectedTabs.join(",")})`,
      ([targetTabs]) => {
        const navCards = document.querySelectorAll(".nav-card");
        const tabTargets = Array.from(document.querySelectorAll('.tab[role="tab"][data-tab-target]'))
          .filter((button) => !button.hidden)
          .map((button) => button.dataset.tabTarget || "");
        return (
          navCards.length === 0 &&
          tabTargets.join(",") === targetTabs.join(",")
        );
      },
      [expectedTabs],
      timeout
    );
  }

  async function assertHeroResponsePanelState(expectedState, timeout = 10000) {
    await waitForPageCondition(
      `hero response panel state (${expectedState})`,
      ([targetState]) => {
        const panel = document.getElementById("heroResponsePanel");
        const responseArea = document.getElementById("responseArea");
        return Boolean(
          panel &&
          responseArea &&
          panel.dataset.panelState === targetState &&
          responseArea.dataset.panelState === targetState
        );
      },
      [expectedState],
      timeout
    );
  }

  async function waitForTabState(tabName, options = {}, timeout = 10000) {
    const { focused = false } = options;
    await waitForPageCondition(
      `waitForTabState(${tabName})`,
      ([targetTabName, targetFocused]) => {
        const tabs = Array.from(document.querySelectorAll('.tab[role="tab"][data-tab-target]'));
        const panels = Array.from(document.querySelectorAll('.tab-content[role="tabpanel"]'));
        const activeTab = document.getElementById(`tab-${targetTabName}`);
        const activePanel = document.getElementById(`${targetTabName}-tab`);

        if (!activeTab || !activePanel) {
          return false;
        }

        const activeTabOk =
          activeTab.classList.contains("active") &&
          activeTab.getAttribute("aria-selected") === "true" &&
          activeTab.getAttribute("tabindex") === "0";
        const activePanelOk = activePanel.classList.contains("active") && activePanel.hidden === false;
        const inactiveTabsOk = tabs.every((tab) =>
          tab === activeTab ||
          (!tab.classList.contains("active") &&
            tab.getAttribute("aria-selected") === "false" &&
            tab.getAttribute("tabindex") === "-1")
        );
        const inactivePanelsOk = panels.every((panel) =>
          panel === activePanel || (panel.classList.contains("active") === false && panel.hidden === true)
        );
        const focusOk = !targetFocused || document.activeElement === activeTab;

        return activeTabOk && activePanelOk && inactiveTabsOk && inactivePanelsOk && focusOk;
      },
      [tabName, focused],
      timeout
    );
  }

  async function assertTopTabContract({
    lang = "ru",
    viewportLabel = "desktop",
    expectedActive = "upload",
    verifyFocusOrder = true,
    timeout = 10000,
  } = {}) {
    await switchLanguage(lang);
    await waitForPageCondition(
      `top tab contract ${viewportLabel} ${lang}`,
      ([expectedTabs, expectedLabels, activeTarget]) => {
        const tabs = Array.from(document.querySelectorAll('.mode-tabs .tab[role="tab"][data-tab-target]'));
        const activeTab = document.getElementById(`tab-${activeTarget}`);
        const activePanel = document.getElementById(`${activeTarget}-tab`);
        const domOrderOk =
          tabs.length === expectedTabs.length &&
          tabs.every((tab, index) => (
            tab.id === expectedTabs[index].id &&
            tab.dataset.tabTarget === expectedTabs[index].target &&
            tab.dataset.toolEntry === expectedTabs[index].target &&
            tab.dataset.i18n === expectedTabs[index].key &&
            tab.textContent.trim() === expectedLabels[index] &&
            !tab.hidden
          ));
        const rects = tabs.map((tab) => {
          const rect = tab.getBoundingClientRect();
          return {
            id: tab.id,
            left: Math.round(rect.left),
            top: Math.round(rect.top),
            width: Math.round(rect.width),
            height: Math.round(rect.height),
          };
        });
        const visualOrder = rects
          .slice()
          .sort((a, b) => (a.top - b.top) || (a.left - b.left))
          .map((item) => item.id);
        const expectedIds = expectedTabs.map((tab) => tab.id);
        const visibleOk = rects.every((rect) => rect.width > 0 && rect.height > 0);
        const activeOk = Boolean(
          activeTab &&
          activePanel &&
          activeTab.classList.contains("active") &&
          activeTab.getAttribute("aria-selected") === "true" &&
          activeTab.getAttribute("tabindex") === "0" &&
          activePanel.classList.contains("active") &&
          activePanel.hidden === false
        );
        return domOrderOk && visibleOk && visualOrder.join(",") === expectedIds.join(",") && activeOk;
      },
      [topTabContract, topTabLabels[lang], expectedActive],
      timeout
    );

    if (!verifyFocusOrder) {
      return;
    }

    await page.locator("#tab-upload").focus();
    await waitForPageCondition(
      `top tab focus starts at upload ${viewportLabel}`,
      () => document.activeElement?.id === "tab-upload",
      null,
      timeout
    );
    for (const target of ["files", "request", "opsec", "notepad"]) {
      await page.keyboard.press("ArrowRight");
      await waitForTabState(target, { focused: true }, timeout);
    }
    await page.keyboard.press("Home");
    await waitForTabState("upload", { focused: true }, timeout);
  }

  async function assertDirectHashTabRoutes(timeout = 10000) {
    for (const tab of topTabContract) {
      await page.goto(`${rootUrl}#${tab.target}`, { waitUntil: "domcontentloaded" });
      await waitForSpaReady();
      await waitForAdvancedUploadReady();
      await waitForTabState(tab.target, {}, timeout);
    }
  }

  async function waitForUploadMethodState(method, options = {}, timeout = 10000) {
    const { focused = false } = options;
    await waitForPageCondition(
      `waitForUploadMethodState(${method})`,
      ([targetMethod, targetFocused]) => {
        const buttons = Array.from(document.querySelectorAll('.upload-method-btn[data-upload-method]'));
        const activeButton = buttons.find((button) => button.dataset.uploadMethod === targetMethod);
        if (!activeButton) {
          return false;
        }

        const activeOk =
          activeButton.classList.contains("active") &&
          activeButton.getAttribute("aria-checked") === "true" &&
          activeButton.getAttribute("tabindex") === "0";
        const inactiveOk = buttons.every((button) =>
          button === activeButton ||
          (!button.classList.contains("active") &&
            button.getAttribute("aria-checked") === "false" &&
            button.getAttribute("tabindex") === "-1")
        );
        const hint = document.getElementById("uploadMethodHint");
        const hintOk = Boolean(hint && hint.innerText.includes(targetMethod));
        const focusOk = !targetFocused || document.activeElement === activeButton;

        return activeOk && inactiveOk && hintOk && focusOk;
      },
      [method, focused],
      timeout
    );
  }

  async function ensureRequestBatchMismatchCounter(timeout = 10000) {
    await page.evaluate(() => {
      window.XferryApp.invoke("requests", "record-batch-result", "GET", "/index.html", {
        kind: "response",
        status: 404,
        statusText: "Not Found",
      });
      const details = document.getElementById("requestBatchDetails");
      if (details) details.open = true;
    });
    await waitForPageCondition(
      "request batch mismatch counter rendered",
      () => {
        const summary = document.getElementById("requestBatchSummary");
        return Boolean(
          summary &&
          summary.hidden === false &&
          summary.dataset.batchMismatchCount === "1"
        );
      },
      null,
      timeout
    );
  }

  async function assertLocaleSnapshot({
    uploadTabText,
    filesTabText,
    requestTabText,
    opsecTabText,
    notepadTabText,
    brandTaglineText,
    heroTitleText,
    mismatchLabelText,
    smuggleActionLabelText,
    forbiddenText = null,
    noteListText,
    charCountText,
    themeLabel,
    notepadTitleMetadataHintText,
    notepadEphemeralWarningText,
    notepadTextareaLabelText,
  }) {
    await waitForText(page.locator("#tab-upload"), uploadTabText);
    await waitForText(page.locator("#tab-files"), filesTabText);
    await waitForText(page.locator("#tab-request"), requestTabText);
    await waitForText(page.locator("#tab-opsec"), opsecTabText);
    await waitForText(page.locator("#tab-notepad"), notepadTabText);
    if (brandTaglineText) {
      await waitForPageCondition(
        "brand tagline translated",
        ([expectedText]) => {
          const tagline = document.querySelector(".brand-copy p");
          return Boolean(tagline && tagline.textContent.trim() === expectedText);
        },
        [brandTaglineText],
        10000
      );
    }
    if (heroTitleText) {
      await waitForPageCondition(
        "request hero title translated",
        ([expectedText]) => {
          const heading = document.querySelector("#request-tab h2");
          return Boolean(heading && heading.textContent.trim() === expectedText);
        },
        [heroTitleText],
        10000
      );
    }
    if (mismatchLabelText) {
      await ensureRequestBatchMismatchCounter();
      await waitForPageCondition(
        "request matrix mismatch label translated",
        ([expectedText, rejectedText]) => {
          const labels = Array.from(
            document.querySelectorAll("#requestBatchSummary .request-batch-summary__count-label")
          ).map((label) => label.textContent.trim());
          return labels.includes(expectedText) && (!rejectedText || !labels.includes(rejectedText));
        },
        [mismatchLabelText, forbiddenText],
        10000
      );
    }
    if (smuggleActionLabelText) {
      await waitForPageCondition(
        "file smuggle action label translated",
        ([expectedText]) => {
          const buttons = Array.from(document.querySelectorAll("[data-file-action='smuggle']"));
          return buttons.length > 0 && buttons.every((button) => button.textContent.trim() === expectedText);
        },
        [smuggleActionLabelText],
        10000
      );
    }
    await waitForPageCondition("mode tabs are ordered", () => {
      const ids = Array.from(document.querySelectorAll('.tab[role="tab"][data-tab-target]')).map((tab) => tab.id);
      return ids.join(",") === "tab-upload,tab-files,tab-request,tab-opsec,tab-notepad";
    });
    await waitForText(page.locator("#notepadNoteList"), noteListText);
    await waitForText(page.locator("#notepadCharCount"), charCountText);
    if (notepadTitleMetadataHintText) {
      await waitForText(page.locator("#notepadTitleMetadataHint"), notepadTitleMetadataHintText);
    }
    if (notepadEphemeralWarningText) {
      await waitForText(page.locator("#notepadEphemeralWarning"), notepadEphemeralWarningText);
    }
    if (notepadTextareaLabelText) {
      await waitForPageCondition(
        "notepad textarea label translated",
        ([expectedText]) => {
          const label = document.getElementById("notepadTextareaLabel");
          return Boolean(label && label.textContent.trim() === expectedText);
        },
        [notepadTextareaLabelText]
      );
    }
    await waitForPageCondition(
      `theme button translated (${themeLabel})`,
      ([expectedLabel]) => {
        const button = document.getElementById("themeBtn");
        return Boolean(
          button &&
          button.title === expectedLabel &&
          button.getAttribute("aria-label") === expectedLabel
        );
      },
      [themeLabel],
      10000
    );
  }

  async function waitForFilesSummaryText(expectedText, timeout = 10000) {
    const expectedItems = Array.isArray(expectedText) ? expectedText : [expectedText];
    await waitForPageCondition(
      `waitForFilesSummaryText(${expectedItems.join(" | ")})`,
      ([items]) => {
        const root = document.querySelector('[data-tool-summary-scope="files"]');
        const content = root?.innerText || root?.textContent || "";
        return Boolean(
          root &&
          root.dataset.phase &&
          items.every((item) => content.includes(item))
        );
      },
      [expectedItems],
      timeout
    );
  }

  async function assertFilesRefreshPreservesCompletedSummary(expectedText, label, timeout = 15000) {
    const expectedItems = Array.isArray(expectedText) ? expectedText : [expectedText];
    await waitForPageCondition(
      `files automatic refresh preserves ${label}`,
      ([items]) => {
        const summaryRoot = document.querySelector('[data-tool-summary-scope="files"]');
        const browseStatus = document.getElementById("filesBrowseStatus");
        const summaryText = (summaryRoot?.innerText || summaryRoot?.textContent || "").trim();
        const browseStatusText = (browseStatus?.innerText || browseStatus?.textContent || "").trim();
        return Boolean(
          summaryRoot &&
          browseStatus &&
          summaryRoot.dataset.phase === "complete" &&
          items.every((item) => summaryText.includes(item)) &&
          browseStatusText.length > 0 &&
          browseStatus.dataset.browsePhase === "complete" &&
          !items.every((item) => browseStatusText.includes(item))
        );
      },
      [expectedItems],
      timeout
    );
  }

  async function assertUploadSendEmptyState(timeout = 10000) {
    await waitForPageCondition(
      "upload Send empty state",
      () => {
        const summary = document.querySelector('[data-tool-summary-scope="upload"]');
        const trace = document.querySelector('[data-tool-trace-scope="upload"]');
        const dropZone = document.getElementById("dropZone");
        const uploadButton = document.getElementById("uploadBtn");
        const fileInputs = document.querySelectorAll("#upload-tab input[type='file']");
        const actions = summary?.querySelector("[data-tool-summary-actions]");
        const text = (summary?.innerText || summary?.textContent || "").trim();
        const dropRect = dropZone?.getBoundingClientRect();
        const buttonRect = uploadButton?.getBoundingClientRect();
        return Boolean(
          summary &&
          summary.dataset.phase === "empty" &&
          text.length > 0 &&
          text.length <= 180 &&
          /Choose|Выберите/.test(text) &&
          /Send|Отправить/.test(text) &&
          trace &&
          trace.open === false &&
          dropZone &&
          dropRect &&
          dropRect.width > 0 &&
          dropRect.height > 0 &&
          uploadButton &&
          uploadButton.disabled &&
          buttonRect &&
          buttonRect.width > 0 &&
          buttonRect.height > 0 &&
          fileInputs.length === 1 &&
          fileInputs[0].tabIndex === -1 &&
          (!actions || actions.hidden || !(actions.innerText || "").trim())
        );
      },
      null,
      timeout
    );
    await page.locator("#dropZone").focus();
    await waitForPageCondition(
      "upload chooser is the visible keyboard entry",
      () => document.activeElement?.id === "dropZone",
      null,
      timeout
    );
    await page.keyboard.press("Tab");
    await waitForPageCondition(
      "clipped upload file input is skipped by keyboard",
      () => {
        const active = document.activeElement;
        const fileInput = document.getElementById("fileInput");
        const rect = active?.getBoundingClientRect();
        return Boolean(
          active &&
          active !== fileInput &&
          rect &&
          rect.width > 0 &&
          rect.height > 0
        );
      },
      null,
      timeout
    );
  }

  async function assertUploadChooserReady(timeout = 10000) {
    await waitForPageCondition(
      "upload chooser ready",
      () => {
        const dropZone = document.getElementById("dropZone");
        const uploadButton = document.getElementById("uploadBtn");
        const fileInput = document.getElementById("fileInput");
        const dropRect = dropZone?.getBoundingClientRect();
        const buttonRect = uploadButton?.getBoundingClientRect();
        return Boolean(
          dropZone &&
          dropRect &&
          dropRect.width > 0 &&
          dropRect.height > 0 &&
          fileInput &&
          !fileInput.disabled &&
          uploadButton &&
          uploadButton.disabled &&
          buttonRect &&
          buttonRect.width > 0 &&
          buttonRect.height > 0
        );
      },
      null,
      timeout
    );
  }

  async function assertUploadPrimaryActionDoesNotShiftAfterSelection() {
    await page.locator("#fileInput").setInputFiles([]);
    await assertUploadSendEmptyState();
    const empty = await page.evaluate(() => {
      const container = document.querySelector("#upload-tab .upload-primary-action");
      const buttons = document.querySelector(
        "#upload-tab .upload-primary-action__buttons"
      );
      const selection = document.getElementById("uploadSelectionState");
      if (!container || !buttons || !selection) {
        throw new Error("Upload primary action geometry targets are missing");
      }
      const containerRect = container.getBoundingClientRect();
      const buttonsRect = buttons.getBoundingClientRect();
      return {
        containerRight: containerRect.right,
        buttonsLeft: buttonsRect.left,
        buttonsRight: buttonsRect.right,
        selectionHidden: selection.hidden,
        selectionText: selection.textContent?.trim() || "",
      };
    });

    await page.locator("#fileInput").setInputFiles(uploadFilePath);
    await waitForPageCondition(
      "upload selection enables the primary action",
      () => {
        const selection = document.getElementById("uploadSelectionState");
        const button = document.getElementById("uploadBtn");
        return Boolean(selection && !selection.hidden && button && !button.disabled);
      }
    );
    const selected = await page.evaluate(() => {
      const container = document.querySelector("#upload-tab .upload-primary-action");
      const buttons = document.querySelector(
        "#upload-tab .upload-primary-action__buttons"
      );
      if (!container || !buttons) {
        throw new Error("Upload primary action geometry targets are missing");
      }
      const containerRect = container.getBoundingClientRect();
      const buttonsRect = buttons.getBoundingClientRect();
      return {
        containerRight: containerRect.right,
        buttonsLeft: buttonsRect.left,
        buttonsRight: buttonsRect.right,
      };
    });

    const tolerance = 1;
    if (
      empty.selectionHidden ||
      !/^(No files selected|Файлы не выбраны)$/.test(empty.selectionText) ||
      Math.abs(empty.containerRight - empty.buttonsRight) > tolerance ||
      Math.abs(selected.containerRight - selected.buttonsRight) > tolerance ||
      Math.abs(empty.buttonsLeft - selected.buttonsLeft) > tolerance ||
      Math.abs(empty.buttonsRight - selected.buttonsRight) > tolerance
    ) {
      throw new Error(
        `Upload primary action shifted after file selection: ${JSON.stringify({
          empty,
          selected,
        })}`
      );
    }

    await page.locator('#fileList [data-remove-index="0"]').click();
    await assertUploadSendEmptyState();
    return { empty, selected };
  }

  async function assertResponsiveUploadSummaryAndActions() {
    await page.setViewportSize({ width: 1440, height: 1024 });
    await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForAdvancedUploadReady();
    const desktop = await page.evaluate(() => {
      const summary = document.getElementById("uploadRequestSummary");
      const action = document.querySelector("#upload-tab .upload-primary-action");
      const buttons = document.querySelector("#upload-tab .upload-primary-action__buttons");
      return {
        summaryIsDetails: summary instanceof HTMLDetailsElement,
        summaryOpen: summary?.open === true,
        documentWidth: document.documentElement.scrollWidth,
        viewportWidth: innerWidth,
        actionDirection: action ? getComputedStyle(action).flexDirection : "",
        buttonsColumns: buttons ? getComputedStyle(buttons).gridTemplateColumns : "",
      };
    });
    await page.screenshot({
      path: `${artifactDir}/task4-upload-desktop.png`,
      fullPage: true,
    });

    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForAdvancedUploadReady();
    const mobile = await page.evaluate(() => {
      const summary = document.getElementById("uploadRequestSummary");
      const action = document.querySelector("#upload-tab .upload-primary-action");
      const buttons = document.querySelector("#upload-tab .upload-primary-action__buttons");
      const panel = document.querySelector("#upload-tab .tool-card--workflow");
      return {
        summaryIsDetails: summary instanceof HTMLDetailsElement,
        summaryOpen: summary?.open === true,
        documentWidth: document.documentElement.scrollWidth,
        viewportWidth: innerWidth,
        actionDirection: action ? getComputedStyle(action).flexDirection : "",
        buttonsColumns: buttons ? getComputedStyle(buttons).gridTemplateColumns : "",
        panelRight: panel?.getBoundingClientRect().right || 0,
      };
    });
    await page.screenshot({
      path: `${artifactDir}/task4-upload-mobile.png`,
      fullPage: true,
    });
    await page.setViewportSize({ width: 1440, height: 1024 });
    await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForAdvancedUploadReady();

    if (
      !desktop.summaryIsDetails ||
      !desktop.summaryOpen ||
      desktop.documentWidth > desktop.viewportWidth + 1 ||
      !mobile.summaryIsDetails ||
      mobile.summaryOpen ||
      mobile.actionDirection !== "column" ||
      mobile.buttonsColumns.split(/\s+/).length !== 1 ||
      mobile.documentWidth > mobile.viewportWidth + 1 ||
      mobile.panelRight > mobile.viewportWidth + 1
    ) {
      throw new Error(
        `Responsive upload summary/action contract failed: ${JSON.stringify({ desktop, mobile })}`
      );
    }
    return { desktop, mobile };
  }

  async function uploadViaDom(name, filePath = uploadFilePath) {
    await page.locator("#tab-upload").click();
    await waitForTabState("upload", { focused: true });
    await assertUploadChooserReady();
    await page.locator("#fileInput").setInputFiles(filePath);

    await waitForPageCondition("upload button enabled", () => {
      const uploadBtn = document.getElementById("uploadBtn");
      return Boolean(uploadBtn && !uploadBtn.disabled);
    }, null, 10000);

    const selectedSizeText = await page.locator(`#fileList .file-item:has-text("${name}") .file-size`).innerText();
    await waitForPageCondition(
      "upload request preview ready before send",
      ([targetPath]) => {
        const trace = document.querySelector('[data-tool-trace-scope="upload"]');
        const area = document.getElementById("uploadRequestArea");
        return Boolean(
          trace &&
          area &&
          area.dataset.exchangePhase === "ready" &&
          area.dataset.exchangePath === targetPath
        );
      },
      ["/uploads"],
      10000
    );

    await page.locator("#uploadBtn").click();
    await waitForLiveRegionText(
      "uploadResponseAreaLive",
      /Загрузка завершена|Upload complete/,
      10000
    );
    await waitForPageCondition(
      "upload success summary",
      ([targetName, targetSize]) => {
        const summary = document.querySelector('[data-tool-summary-scope="upload"]');
        const trace = document.querySelector('[data-tool-trace-scope="upload"]');
        const status = summary?.querySelector('[data-upload-result-field="status"]');
        const serverPath = summary?.querySelector('[data-upload-result-field="server-path"]');
        const size = summary?.querySelector('[data-upload-result-field="size"]');
        const statusValue = status?.querySelector(".tool-result__meta-value");
        const serverPathValue = serverPath?.querySelector(".tool-result__meta-value");
        const sizeValue = size?.querySelector(".tool-result__meta-value");
        const traceAction = summary?.querySelector('[data-upload-response-action="show-trace"]');
        const filesAction = summary?.querySelector('[data-upload-response-action="view-files"]');
        const text = summary?.innerText || summary?.textContent || "";
        const traceActionText = traceAction?.textContent || "";
        return Boolean(
          summary &&
          summary.dataset.phase === "complete" &&
          trace &&
          text.includes(targetName) &&
          statusValue &&
          statusValue.textContent.includes("201") &&
          serverPathValue &&
          serverPathValue.textContent.trim() === `/uploads/${targetName}` &&
          sizeValue &&
          sizeValue.textContent.trim() === targetSize &&
          traceAction &&
          traceAction.getBoundingClientRect().width > 0 &&
          /Inspect|technical details|технические детали/i.test(traceActionText) &&
          filesAction &&
          filesAction.getBoundingClientRect().width > 0 &&
          /Files|Файлы/.test(filesAction.textContent || "")
        );
      },
      [name, selectedSizeText.trim()],
      15000
    );
    await page.locator('[data-upload-response-action="show-trace"]').click();
    await waitForPageCondition(
      "upload Inspect opens inline trace",
      () => {
        const trace = document.querySelector('[data-tool-trace-scope="upload"]');
        const responseArea = document.getElementById("uploadResponseArea");
        return Boolean(
          trace &&
          trace.open &&
          responseArea &&
          responseArea.dataset.exchangePhase === "complete" &&
          responseArea.innerText.includes("HTTP/1.1 201")
        );
      },
      null,
      10000
    );
    await assertExchangeDownload(
      "uploadRequestArea",
      [
        "POST /uploads HTTP/1.1",
        "Content-Type: multipart/form-data; boundary=<browser-generated>",
        "Content-Length: <browser-generated>",
      ],
      /^xferry-upload-request-.*\.http$/
    );
    await assertExchangeDownload(
      "uploadResponseArea",
      ["HTTP/1.1 201"],
      /^xferry-upload-response-.*\.http$/
    );
    await page.locator('[data-upload-response-action="view-files"]').click();
    await waitForTabState("files", {}, 10000);

    return { selectedSizeText: selectedSizeText.trim() };
  }

  async function assertMultipleFileSelectionSummary() {
    const firstName = uploadFilePath.split(/[\\/]/).pop();
    const secondName = opsecUploadUrlBoundaryFilePath.split(/[\\/]/).pop();
    await page.locator("#tab-upload").click();
    await waitForTabState("upload", { focused: true });
    await switchLanguage("ru");
    await page.locator("#fileInput").setInputFiles([
      uploadFilePath,
      opsecUploadUrlBoundaryFilePath,
    ]);
    await waitForPageCondition(
      "two-file Russian selection summary",
      ([expectedSummary, expectedButton]) => {
        const summary = document.getElementById("uploadSelectionState");
        const button = document.getElementById("uploadBtn");
        return Boolean(
          summary &&
          !summary.hidden &&
          summary.textContent === expectedSummary &&
          button &&
          button.textContent.trim() === expectedButton &&
          !button.disabled &&
          document.querySelectorAll("#fileList .file-item").length === 2
        );
      },
      ["Файлов выбрано: 2 (1.1 KB)", "Отправить"]
    );

    await switchLanguage("en");
    await waitForPageCondition(
      "two-file English selection summary",
      ([expectedSummary, expectedButton]) => {
        const summary = document.getElementById("uploadSelectionState");
        const button = document.getElementById("uploadBtn");
        return Boolean(
          summary?.textContent === expectedSummary &&
          button?.textContent.trim() === expectedButton
        );
      },
      ["Files selected: 2 (1.1 KB)", "Send"]
    );

    await page.locator('#fileList [data-remove-index="1"]').click();
    await waitForPageCondition(
      "single-file English selection summary after remove",
      ([expectedSummary, expectedButton, removedName]) => {
        const summary = document.getElementById("uploadSelectionState");
        const button = document.getElementById("uploadBtn");
        const list = document.getElementById("fileList");
        return Boolean(
          summary?.textContent === expectedSummary &&
          button?.textContent.trim() === expectedButton &&
          list &&
          !list.textContent.includes(removedName) &&
          list.querySelectorAll(".file-item").length === 1
        );
      },
      [`Selected: ${firstName} (21 B)`, "Send", secondName]
    );

    await switchLanguage("ru");
    await waitForPageCondition(
      "single-file Russian selection summary after remove",
      ([expectedSummary, expectedButton]) => {
        const summary = document.getElementById("uploadSelectionState");
        const button = document.getElementById("uploadBtn");
        return Boolean(
          summary?.textContent === expectedSummary &&
          button?.textContent.trim() === expectedButton
        );
      },
      [`Выбрано: ${firstName} (21 B)`, "Отправить"]
    );
    await page.locator('#fileList [data-remove-index="0"]').click();
    await assertUploadSendEmptyState();
    return {
      files: [firstName, secondName],
      total: "1.1 KB",
      remaining: `${firstName} (21 B)`,
    };
  }

  async function openToolTrace(scope) {
    await page.evaluate((targetScope) => {
      const details = document.querySelector(`[data-tool-trace-scope="${targetScope}"]`);
      if (details) {
        details.open = true;
      }
    }, scope);
  }

  async function readDownloadText(download) {
    const stream = await download.createReadStream();
    if (!stream) {
      throw new Error(`Downloaded file is unavailable: ${download.suggestedFilename()}`);
    }

    stream.setEncoding("utf8");
    let content = "";
    for await (const chunk of stream) {
      content += chunk;
    }
    return content;
  }

  async function captureNextBlobDownload(trigger, timeout = 10000) {
    await page.evaluate(() => {
      const blobUrlApi = window.URL || window.webkitURL;
      if (!blobUrlApi?.createObjectURL) {
        throw new Error("Blob URLs are unavailable");
      }
      if (window.__xferryBlobDownloadCapture) {
        throw new Error("A Blob download capture is already installed");
      }

      const originalCreateObjectUrl = blobUrlApi.createObjectURL;
      const originalAnchorClick = HTMLAnchorElement.prototype.click;
      const capture = {
        blob: null,
        filename: "",
        originalCreateObjectUrl,
        originalAnchorClick,
      };
      window.__xferryBlobDownloadCapture = capture;
      blobUrlApi.createObjectURL = function createCapturedObjectUrl(blob) {
        capture.blob = blob;
        return originalCreateObjectUrl.call(this, blob);
      };
      HTMLAnchorElement.prototype.click = function clickCapturedDownload() {
        if (this.download && String(this.href || "").startsWith("blob:")) {
          capture.filename = this.download;
          return;
        }
        return originalAnchorClick.call(this);
      };
    });

    try {
      await trigger();
      await waitForPageCondition(
        "Blob download captured",
        () => Boolean(
          window.__xferryBlobDownloadCapture?.blob &&
          window.__xferryBlobDownloadCapture?.filename
        ),
        null,
        timeout
      );
      return await page.evaluate(async () => {
        const capture = window.__xferryBlobDownloadCapture;
        return {
          filename: capture.filename,
          content: await capture.blob.text(),
        };
      });
    } finally {
      await page.evaluate(() => {
        const capture = window.__xferryBlobDownloadCapture;
        if (!capture) {
          return;
        }
        const blobUrlApi = window.URL || window.webkitURL;
        blobUrlApi.createObjectURL = capture.originalCreateObjectUrl;
        HTMLAnchorElement.prototype.click = capture.originalAnchorClick;
        delete window.__xferryBlobDownloadCapture;
      });
    }
  }

  async function assertExchangeDownload(
    areaId,
    expectedText = [],
    filenamePattern = /\.http$/,
    forbiddenText = [],
    timeout = 10000,
  ) {
    await waitForPageCondition(
      `exchange download enabled (${areaId})`,
      ([targetAreaId]) => {
        const button = document.querySelector(`[data-exchange-download-area="${targetAreaId}"]`);
        return Boolean(button && !button.disabled);
      },
      [areaId],
      timeout
    );

    const downloadPromise = page.waitForEvent("download");
    await page.locator(`[data-exchange-download-area="${areaId}"]`).click();
    const download = await downloadPromise;
    const suggestedFilename = download.suggestedFilename();
    const snapshot = {
      areaId,
      filename: suggestedFilename,
      content: await readDownloadText(download),
    };

    if (snapshot.areaId !== areaId) {
      throw new Error(`Exchange download area mismatch: ${snapshot.areaId} !== ${areaId}`);
    }
    if (snapshot.filename !== suggestedFilename) {
      throw new Error(`Exchange download filename mismatch: ${snapshot.filename} !== ${suggestedFilename}`);
    }
    if (!filenamePattern.test(snapshot.filename)) {
      throw new Error(`Unexpected exchange download filename: ${snapshot.filename}`);
    }
    for (const item of expectedText) {
      if (!snapshot.content.includes(item)) {
        throw new Error(`Exchange download ${areaId} missing "${item}": ${snapshot.content}`);
      }
    }
    for (const item of forbiddenText) {
      if (snapshot.content.includes(item)) {
        throw new Error(`Exchange download ${areaId} unexpectedly includes "${item}": ${snapshot.content}`);
      }
    }
  }

  async function browseUploadsAndAssert(name) {
    await page.locator("#tab-files").click();
    await waitForTabState("files", { focused: true });
    await page.locator("#browsePathInput").fill("/uploads");
    await page.getByRole("button", { name: /^(Обзор(?: \(INFO\))?|Browse(?: \(INFO\))?)$/ }).click();
    await waitForPageCondition(
      `uploads browse shows ${name}`,
      ([targetName]) => {
        const list = document.getElementById("serverFiles");
        const content = list?.innerText || list?.textContent || "";
        return Boolean(list && content.includes(targetName));
      },
      [name],
      10000
    );
    await waitForPageCondition(
      `uploads browse completed (${name})`,
      () => {
        const status = document.getElementById("filesBrowseStatus");
        const list = document.getElementById("serverFiles");
        return Boolean(
          status &&
          status.dataset.browsePhase === "complete" &&
          list &&
          list.getAttribute("aria-busy") === "false"
        );
      },
      null,
      10000
    );
  }

  async function waitForRequestPanelResponse(method, status, path, timeout = 15000) {
    await waitForPageCondition(
      `waitForRequestPanelResponse(${method},${status},${path})`,
      ([targetMethod, targetStatus, targetPath]) => {
        const responseArea = document.getElementById("responseArea");
        return Boolean(
          responseArea &&
          responseArea.dataset.requestPhase === "complete" &&
          responseArea.dataset.requestMethod === targetMethod &&
          responseArea.dataset.requestStatus === String(targetStatus) &&
          responseArea.dataset.requestPath === targetPath
        );
      },
      [method, status, path],
      timeout
    );
  }

  async function waitForRequestPreview(method, path, timeout = 15000) {
    await waitForPageCondition(
      `waitForRequestPreview(${method},${path})`,
      ([targetMethod, targetPath]) => {
        const section = document.getElementById("requestPreviewSection");
        const previewArea = document.getElementById("requestPreviewArea");
        return Boolean(
          section &&
          previewArea &&
          section.hidden === false &&
          previewArea.dataset.requestPhase === "ready" &&
          previewArea.dataset.requestMethod === targetMethod &&
          previewArea.dataset.requestPath === targetPath
        );
      },
      [method, path],
      timeout
    );
  }

  async function assertRequestPreviewVisibility(expectedVisible, timeout = 10000) {
    await waitForPageCondition(
      `assertRequestPreviewVisibility(${expectedVisible})`,
      ([targetVisible]) => {
        const section = document.getElementById("requestPreviewSection");
        const visibleOk = section && section.hidden === !targetVisible;
        return Boolean(section && visibleOk);
      },
      [expectedVisible],
      timeout
    );
  }

  async function assertRequestPreviewModeState(expectedMode, timeout = 10000) {
    await waitForPageCondition(
      `assertRequestPreviewModeState(${expectedMode})`,
      ([targetMode]) => {
        const buttons = Array.from(document.querySelectorAll("[data-request-preview-mode]"));
        const previewArea = document.getElementById("requestPreviewArea");
        return Boolean(
          previewArea &&
          previewArea.dataset.requestView === targetMode &&
          buttons.length === 2 &&
          buttons.every((button) => {
            const isActive = button.dataset.requestPreviewMode === targetMode;
            return (
              button.classList.contains("active") === isActive &&
              button.getAttribute("aria-checked") === String(isActive) &&
              button.getAttribute("tabindex") === (isActive ? "0" : "-1")
            );
          })
        );
      },
      [expectedMode],
      timeout
    );
  }

  async function assertResponseViewState(expectedMode, timeout = 10000) {
    await waitForPageCondition(
      `assertResponseViewState(${expectedMode})`,
      ([targetMode]) => {
        const responseArea = document.getElementById("responseArea");
        return Boolean(responseArea && responseArea.dataset.requestView === targetMode);
      },
      [expectedMode],
      timeout
    );
  }

  async function openRequestTechnicalDetails({ includeBatch = false, timeout = 10000 } = {}) {
    await waitForTabState("request", {}, timeout);
    const technical = page.locator("#requestTechnicalDetails");
    if (!(await technical.evaluate((element) => element.open))) {
      await page.locator("#requestTechnicalDetails > summary").focus();
      await page.keyboard.press("Enter");
    }
    await waitForPageCondition(
      "request technical details open",
      () => document.getElementById("requestTechnicalDetails")?.open === true,
      null,
      timeout
    );

    if (!includeBatch) {
      return;
    }

    const batch = page.locator("#requestBatchDetails");
    if (!(await batch.evaluate((element) => element.open))) {
      await page.locator("#requestBatchDetails > summary").focus();
      await page.keyboard.press("Enter");
    }
    await waitForPageCondition(
      "request batch details open",
      () => document.getElementById("requestBatchDetails")?.open === true,
      null,
      timeout
    );
  }

  async function assertRequestPreviewStorageContract(timeout = 10000) {
    await page.goto(`${rootUrl}#request`, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await page.evaluate(() => localStorage.removeItem("requestPreviewMode"));
    await page.reload({ waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForTabState("request", {}, timeout);
    await assertRequestPreviewModeState("summary", timeout);
    await assertResponseViewState("summary", timeout);
    await waitForText(page.locator("#requestPreviewArea"), /Выберите метод|Choose a method/, timeout);

    await openRequestTechnicalDetails({ timeout });
    await page.locator('[data-request-preview-mode="raw"]').click();
    await assertRequestPreviewModeState("raw", timeout);
    await assertResponseViewState("raw", timeout);
    await page.reload({ waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForTabState("request", {}, timeout);
    await assertRequestPreviewModeState("raw", timeout);
    await assertResponseViewState("raw", timeout);
  }

  async function assertRequestTechnicalDetailsReachable(expectedMethods, timeout = 10000) {
    await page.locator("#tab-request").click();
    await waitForTabState("request", { focused: true }, timeout);
    await page.evaluate(() => {
      const technical = document.getElementById("requestTechnicalDetails");
      const batch = document.getElementById("requestBatchDetails");
      if (technical) technical.open = false;
      if (batch) batch.open = false;
    });

    await page.locator("#requestTechnicalDetails > summary").focus();
    await page.keyboard.press("Enter");
    await waitForPageCondition(
      "request technical details opened by keyboard",
      () => document.getElementById("requestTechnicalDetails")?.open === true,
      null,
      timeout
    );
    await page.locator("#requestBatchDetails > summary").focus();
    await page.keyboard.press("Enter");
    await waitForPageCondition(
      "request batch details opened by keyboard",
      () => document.getElementById("requestBatchDetails")?.open === true,
      null,
      timeout
    );

    await waitForPageCondition(
      "request technical controls are visible inside details",
      ([methods]) => {
        const technical = document.getElementById("requestTechnicalDetails");
        const batchDetails = document.getElementById("requestBatchDetails");
        const isVisible = (element) => {
          if (!element) return false;
          const rect = element.getBoundingClientRect();
          const style = window.getComputedStyle(element);
          return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
        };
        const methodButtons = methods.map((method) =>
          document.querySelector(`#requestTechnicalDetails [data-request-method="${method}"]`)
        );
        const controls = [
          ...methodButtons,
          document.getElementById("requestRunAllBtn"),
          document.querySelector('[data-request-preview-mode="summary"]'),
          document.querySelector('[data-request-preview-mode="raw"]'),
          document.getElementById("requestBatchRerunIssuesBtn"),
          document.getElementById("requestBatchExportBtn"),
        ];
        return Boolean(
          technical &&
          technical.open &&
          batchDetails &&
          batchDetails.open &&
          methodButtons.length === 13 &&
          controls.every((control) => control && technical.contains(control) && isVisible(control)) &&
          methodButtons.every((button) => !button.disabled) &&
          !document.getElementById("requestRunAllBtn")?.disabled
        );
      },
      [expectedMethods],
      timeout
    );

    await page.locator('[data-request-preview-mode="summary"]').click();
    await page.locator('[data-request-preview-mode="summary"]').focus();
    await waitForPageCondition(
      "request summary mode button focused",
      () => document.activeElement?.getAttribute("data-request-preview-mode") === "summary",
      null,
      timeout
    );
    await page.keyboard.press("ArrowRight");
    await assertRequestPreviewModeState("raw", timeout);
    await waitForPageCondition(
      "request raw mode reached by keyboard",
      () => document.activeElement?.getAttribute("data-request-preview-mode") === "raw",
      null,
      timeout
    );
  }

  async function assertClipboardSnapshot(kind, expectedText = [], timeout = 10000) {
    await waitForPageCondition(
      `assertClipboardSnapshot(${kind})`,
      ([tokens]) => {
        const clipboardText = String(window.__xferryBrowserClipboardText || "");
        return clipboardText.length > 0 && tokens.every((token) => clipboardText.includes(token));
      },
      [expectedText],
      timeout
    );

    const snapshot = await page.evaluate(() => ({
      clipboardText: String(window.__xferryBrowserClipboardText || ""),
    }));

    for (const item of expectedText) {
      if (!snapshot.clipboardText.includes(item)) {
        throw new Error(`Clipboard text for ${kind} missing "${item}": ${snapshot.clipboardText}`);
      }
    }
  }

  async function assertRequestBatchExport({
    phase,
    total,
    completed,
    matchCount,
    mismatchCount,
    failedCount,
    expectedMethods = [],
    expectedAttemptCounts = {},
    timeout = 10000,
  }) {
    await waitForPageCondition(
      "request batch export enabled",
      () => {
        const button = document.getElementById("requestBatchExportBtn");
        return Boolean(button && !button.disabled);
      },
      null,
      timeout
    );

    const downloadPromise = page.waitForEvent("download");
    await page.locator("#requestBatchExportBtn").click();
    const download = await downloadPromise;
    const suggestedFilename = download.suggestedFilename();
    const snapshot = {
      filename: suggestedFilename,
      content: await readDownloadText(download),
    };

    if (snapshot.filename !== suggestedFilename) {
      throw new Error(`Batch export filename mismatch: ${snapshot.filename} !== ${suggestedFilename}`);
    }
    if (!/^request-run-summary-.*\.json$/.test(snapshot.filename)) {
      throw new Error(`Unexpected batch export filename: ${snapshot.filename}`);
    }

    let report;
    try {
      report = JSON.parse(snapshot.content);
    } catch (error) {
      throw new Error(`Batch export content is not valid JSON: ${error.message}`);
    }

    if (
      report.phase !== phase ||
      report.total !== total ||
      report.completed !== completed ||
      report.summary?.matchCount !== matchCount ||
      report.summary?.mismatchCount !== mismatchCount ||
      report.summary?.failedCount !== failedCount
    ) {
      throw new Error(`Unexpected batch export summary: ${snapshot.content}`);
    }

    if (!Array.isArray(report.results) || report.results.length !== total) {
      throw new Error(`Unexpected batch export result count: ${snapshot.content}`);
    }

    for (const method of expectedMethods) {
      if (!report.results.some((result) => result.method === method)) {
        throw new Error(`Batch export is missing method ${method}: ${snapshot.content}`);
      }
    }

    for (const [method, expectedAttemptCount] of Object.entries(expectedAttemptCounts)) {
      const result = report.results.find((item) => item.method === method);
      if (!result) {
        throw new Error(`Batch export is missing method ${method} for attempts check: ${snapshot.content}`);
      }
      if (!Array.isArray(result.attempts) || result.attempts.length !== expectedAttemptCount) {
        throw new Error(`Unexpected attempt count for ${method}: ${snapshot.content}`);
      }
      if (
        result.attempts.some((attempt) => (
          attempt.method !== method ||
          typeof attempt.path !== "string" ||
          typeof attempt.expectedStatus !== "string" ||
          typeof attempt.actualStatus !== "string" ||
          typeof attempt.checkState !== "string" ||
          typeof attempt.checkLabel !== "string" ||
          typeof attempt.timestamp !== "string"
        ))
      ) {
        throw new Error(`Invalid attempt payload for ${method}: ${snapshot.content}`);
      }
    }
  }

  async function assertRequestBatchIssuesFilter({
    checked,
    filter,
    visibleCount,
    emptyText = "",
    timeout = 10000,
  }) {
    await waitForPageCondition(
      `assertRequestBatchIssuesFilter(${filter},${visibleCount})`,
      ([targetChecked, targetFilter, targetVisibleCount, targetEmptyText]) => {
        const toggle = document.getElementById("requestBatchIssuesOnlyToggle");
        const summary = document.getElementById("requestBatchSummary");
        const rows = Array.from(document.querySelectorAll("#requestBatchSummary .request-batch-summary__row"));
        const empty = summary?.querySelector(".request-batch-summary__empty");

        return Boolean(
          toggle &&
          summary &&
          toggle.checked === targetChecked &&
          summary.dataset.batchFilter === targetFilter &&
          summary.dataset.batchVisibleCount === String(targetVisibleCount) &&
          rows.length === targetVisibleCount &&
          (
            targetEmptyText
              ? empty && (empty.textContent || "").includes(targetEmptyText)
              : !empty
          )
        );
      },
      [checked, filter, visibleCount, emptyText],
      timeout
    );
  }

  async function assertRequestMethodButtonBatchState({
    method,
    checkState,
    expectedStatus,
    actualStatus,
    timeout = 10000,
  }) {
    await waitForPageCondition(
      `assertRequestMethodButtonBatchState(${method},${checkState})`,
      ([targetMethod, targetCheckState, targetExpectedStatus, targetActualStatus]) => {
        const button = document.querySelector(`.request-method-switch [data-request-method="${targetMethod}"]`);
        const label = button?.getAttribute("aria-label") || "";
        const title = button?.getAttribute("title") || "";
        return Boolean(
          button &&
          button.dataset.batchCheck === targetCheckState &&
          button.dataset.batchExpectedStatus === targetExpectedStatus &&
          button.dataset.batchActualStatus === targetActualStatus &&
          label.includes(targetExpectedStatus) &&
          label.includes(targetActualStatus) &&
          title === label
        );
      },
      [method, checkState, expectedStatus, actualStatus],
      timeout
    );
  }

  async function assertRequestBatchCleared(timeout = 10000) {
    await waitForPageCondition(
      "request batch cleared",
      () => {
        const summary = document.getElementById("requestBatchSummary");
        const exportBtn = document.getElementById("requestBatchExportBtn");
        const rerunIssuesBtn = document.getElementById("requestBatchRerunIssuesBtn");
        const clearBtn = document.getElementById("requestBatchClearBtn");
        const issuesToggle = document.getElementById("requestBatchIssuesOnlyToggle");
        const batchStatus = document.getElementById("requestBatchStatus");
        const methodButtons = Array.from(document.querySelectorAll(".request-method-switch [data-request-method]"));

        return Boolean(
          summary &&
          summary.hidden === true &&
          summary.dataset.batchPhase === "idle" &&
          summary.dataset.batchTotal === "0" &&
          summary.dataset.batchCompleted === "0" &&
          summary.dataset.batchMatchCount === "0" &&
          summary.dataset.batchMismatchCount === "0" &&
          summary.dataset.batchFailedCount === "0" &&
          summary.dataset.batchVisibleCount === "0" &&
          exportBtn &&
          exportBtn.disabled &&
          rerunIssuesBtn &&
          rerunIssuesBtn.disabled &&
          rerunIssuesBtn.dataset.batchIssueCount === "0" &&
          clearBtn &&
          clearBtn.disabled &&
          issuesToggle &&
          !issuesToggle.checked &&
          batchStatus &&
          (batchStatus.textContent || "").trim() === "" &&
          methodButtons.length > 0 &&
          methodButtons.every((button) =>
            !button.dataset.batchCheck &&
            !button.dataset.batchExpectedStatus &&
            !button.dataset.batchActualStatus &&
            !button.hasAttribute("aria-label")
          )
        );
      },
      null,
      timeout
    );
  }

  async function assertNotepadAccessibilityContracts({
    expectedWarningTokens,
    expectedLabelText,
    expectedDetailsTokens,
    timeout = 10000,
  }) {
    await waitForPageCondition(
      "assertNotepadAccessibilityContracts",
      ([warningTokens, labelText, detailsTokens]) => {
        const titleInput = document.getElementById("notepadTitleInput");
        const textarea = document.getElementById("notepadTextarea");
        const label = document.getElementById("notepadTextareaLabel");
        const warning = document.getElementById("notepadEphemeralWarning");
        const details = document.getElementById("notepadLossDetails");
        const detailsBody = document.getElementById("notepadLossDetailsBody");
        if (!titleInput || !textarea || !label || !warning || !details || !detailsBody) {
          return false;
        }

        const textareaLabels = Array.from(textarea.labels || []);
        const describedBy = String(textarea.getAttribute("aria-describedby") || "").split(/\s+/);
        const titleDescribedBy = String(titleInput.getAttribute("aria-describedby") || "").split(/\s+/);
        const warningStyle = window.getComputedStyle(warning);
        const detailsSummary = details.querySelector("summary");
        const warningText = warning.textContent || "";
        const detailsText = detailsBody.textContent || "";
        return (
          label.textContent.trim() === labelText &&
          textareaLabels.includes(label) &&
          warningTokens.every((token) => warningText.includes(token)) &&
          warningStyle.display !== "none" &&
          warningStyle.visibility !== "hidden" &&
          describedBy.includes("notepadEphemeralWarning") &&
          titleDescribedBy.includes("notepadEphemeralWarning") &&
          details.dataset.testid === "notepad-loss-details" &&
          detailsSummary &&
          detailsSummary.getClientRects().length > 0 &&
          detailsTokens.every((token) => detailsText.includes(token))
        );
      },
      [expectedWarningTokens, expectedLabelText, expectedDetailsTokens],
      timeout
    );

    const details = page.locator("#notepadLossDetails");
    await details.evaluate((element) => {
      element.open = false;
    });
    await page.locator("#notepadLossDetails > summary").focus();
    await page.keyboard.press("Enter");
    await waitForPageCondition(
      "Notepad loss disclosure opens by keyboard",
      () => {
        const disclosure = document.getElementById("notepadLossDetails");
        const body = document.getElementById("notepadLossDetailsBody");
        return Boolean(
          disclosure?.open &&
          body &&
          body.getClientRects().length > 0 &&
          document.activeElement === disclosure.querySelector("summary")
        );
      },
      null,
      timeout
    );
    await page.keyboard.press("Enter");
  }

  async function assertRequestBatchRerunIssuesButtonState({
    disabled,
    issueCount,
    timeout = 10000,
  }) {
    await waitForPageCondition(
      `assertRequestBatchRerunIssuesButtonState(${disabled},${issueCount})`,
      ([targetDisabled, targetIssueCount]) => {
        const button = document.getElementById("requestBatchRerunIssuesBtn");
        const label = button?.getAttribute("aria-label") || "";
        const title = button?.getAttribute("title") || "";
        return Boolean(
          button &&
          button.disabled === targetDisabled &&
          button.dataset.batchIssueCount === String(targetIssueCount) &&
          title === label &&
          (
            targetIssueCount > 0
              ? label.includes(String(targetIssueCount))
              : label.length > 0
          )
        );
      },
      [disabled, issueCount],
      timeout
    );
  }

  async function assertNotepadSelectedDeleteButtonState({
    disabled,
    count,
    labelPrefix,
    timeout = 10000,
  }) {
    await waitForPageCondition(
      `assertNotepadSelectedDeleteButtonState(${disabled},${count})`,
      ([targetDisabled, targetCount, expectedPrefix]) => {
        const button = document.getElementById("notepadDeleteSelectedBtn");
        const label = button?.getAttribute("aria-label") || "";
        const title = button?.getAttribute("title") || "";
        return Boolean(
          button &&
          button.disabled === targetDisabled &&
          button.dataset.count === String(targetCount) &&
          title === label &&
          (
            targetCount > 0
              ? label.startsWith(expectedPrefix) && label.includes(String(targetCount))
              : label === expectedPrefix
          )
        );
      },
      [disabled, count, labelPrefix],
      timeout
    );
  }

  async function assertRequestPreviewSummary(method, path, expectedText = [], timeout = 10000) {
    await waitForPageCondition(
      `assertRequestPreviewSummary(${method},${path})`,
      ([targetMethod, targetPath]) => {
        const previewArea = document.getElementById("requestPreviewArea");
        const summaryRoot = previewArea?.querySelector(".request-preview-summary");
        const content = previewArea?.innerText || "";
        return Boolean(
          previewArea &&
          summaryRoot &&
          previewArea.dataset.requestPhase === "ready" &&
          previewArea.dataset.requestMethod === targetMethod &&
          previewArea.dataset.requestPath === targetPath &&
          previewArea.dataset.requestView === "summary" &&
          !content.includes(`${targetMethod} ${targetPath} HTTP/1.1`)
        );
      },
      [method, path],
      timeout
    );

    const previewText = (await page.locator("#requestPreviewArea").innerText()).trim();
    for (const item of expectedText) {
      if (!previewText.includes(item)) {
        throw new Error(`Request preview summary missing "${item}": ${previewText}`);
      }
    }
  }

  async function assertResponseSummary(method, path, expectedText = [], timeout = 10000) {
    await waitForPageCondition(
      `assertResponseSummary(${method},${path})`,
      ([targetMethod, targetPath]) => {
        const responseArea = document.getElementById("responseArea");
        const summaryRoot = responseArea?.querySelector(".response-summary");
        return Boolean(
          responseArea &&
          summaryRoot &&
          responseArea.dataset.requestPhase === "complete" &&
          responseArea.dataset.requestMethod === targetMethod &&
          responseArea.dataset.requestPath === targetPath &&
          responseArea.dataset.requestView === "summary"
        );
      },
      [method, path],
      timeout
    );

    const responseText = (await page.locator("#responseArea").innerText()).trim();
    for (const item of expectedText) {
      if (!responseText.includes(item)) {
        throw new Error(`Response summary missing "${item}": ${responseText}`);
      }
    }
  }

  async function assertResponseRaw(method, path, expectedText = [], timeout = 10000) {
    await waitForPageCondition(
      `assertResponseRaw(${method},${path})`,
      ([targetMethod, targetPath]) => {
        const responseArea = document.getElementById("responseArea");
        const summaryRoot = responseArea?.querySelector(".response-summary");
        return Boolean(
          responseArea &&
          !summaryRoot &&
          responseArea.dataset.requestPhase === "complete" &&
          responseArea.dataset.requestMethod === targetMethod &&
          responseArea.dataset.requestPath === targetPath &&
          responseArea.dataset.requestView === "raw"
        );
      },
      [method, path],
      timeout
    );

    const responseText = (await page.locator("#responseArea").innerText()).trim();
    for (const item of expectedText) {
      if (!responseText.includes(item)) {
        throw new Error(`Raw response missing "${item}": ${responseText}`);
      }
    }
  }

  async function assertRequestPreviewComparison({
    method,
    path,
    expectedStatus,
    actualStatus,
    checkState,
    timeout = 10000,
  }) {
    await waitForPageCondition(
      `assertRequestPreviewComparison(${method},${path},${checkState})`,
      ([targetMethod, targetPath, targetExpectedStatus, targetActualStatus, targetCheckState]) => {
        const previewArea = document.getElementById("requestPreviewArea");
        return Boolean(
          previewArea &&
          previewArea.dataset.requestPhase === "ready" &&
          previewArea.dataset.requestMethod === targetMethod &&
          previewArea.dataset.requestPath === targetPath &&
          previewArea.dataset.requestView === "summary" &&
          previewArea.dataset.requestExpectedStatus === targetExpectedStatus &&
          previewArea.dataset.requestActualStatus === targetActualStatus &&
          previewArea.dataset.requestStatusCheck === targetCheckState
        );
      },
      [method, path, expectedStatus, actualStatus, checkState],
      timeout
    );
  }

  async function waitForRequestBatchSummary({
    phase,
    total,
    completed,
    matchCount,
    mismatchCount,
    failedCount,
    timeout = 60000,
  }) {
    await waitForPageCondition(
      `waitForRequestBatchSummary(${phase})`,
      ([targetPhase, targetTotal, targetCompleted, targetMatchCount, targetMismatchCount, targetFailedCount]) => {
        const summary = document.getElementById("requestBatchSummary");
        return Boolean(
          summary &&
          summary.hidden === false &&
          summary.dataset.batchPhase === targetPhase &&
          summary.dataset.batchTotal === String(targetTotal) &&
          summary.dataset.batchCompleted === String(targetCompleted) &&
          summary.dataset.batchMatchCount === String(targetMatchCount) &&
          summary.dataset.batchMismatchCount === String(targetMismatchCount) &&
          summary.dataset.batchFailedCount === String(targetFailedCount)
        );
      },
      [phase, total, completed, matchCount, mismatchCount, failedCount],
      timeout
    );
  }

  async function assertRequestBatchRow({
    method,
    path,
    expectedStatus,
    actualStatus,
    checkState,
    attemptCount = null,
    rerunOutcome = null,
    rerunOutcomeTone = null,
    timeout = 10000,
  }) {
    await waitForPageCondition(
      `assertRequestBatchRow(${method},${checkState})`,
      ([targetMethod, targetPath, targetExpectedStatus, targetActualStatus, targetCheckState, targetAttemptCount, targetRerunOutcome, targetRerunOutcomeTone]) => {
        const rows = Array.from(document.querySelectorAll("#requestBatchSummary [data-batch-method]"));
        return rows.some((row) => {
          const pathMatches = targetPath ? row.dataset.batchPath === targetPath : true;
          const attemptLabel = row.querySelector(".request-batch-summary__attempts");
          const attemptsMatch = targetAttemptCount
            ? (
              row.dataset.batchAttemptCount === targetAttemptCount &&
              attemptLabel &&
              (attemptLabel.textContent || "").includes(targetAttemptCount)
            )
            : true;
          const outcomeLabel = row.querySelector(".request-batch-summary__rerun-outcome");
          const outcomeMatches = targetRerunOutcome
            ? (
              row.dataset.batchRerunOutcome === targetRerunOutcome &&
              row.dataset.batchRerunOutcomeTone === targetRerunOutcomeTone &&
              outcomeLabel &&
              /Последний повтор|Last rerun/.test(outcomeLabel.textContent || "")
            )
            : true;
          return (
            row.dataset.batchMethod === targetMethod &&
            pathMatches &&
            row.dataset.batchExpectedStatus === targetExpectedStatus &&
            row.dataset.batchActualStatus === targetActualStatus &&
            row.dataset.batchCheck === targetCheckState &&
            attemptsMatch &&
            outcomeMatches
          );
        });
      },
      [
        method,
        path || "",
        expectedStatus,
        actualStatus,
        checkState,
        attemptCount === null ? "" : String(attemptCount),
        rerunOutcome || "",
        rerunOutcomeTone || "",
      ],
      timeout
    );
  }

  async function assertRequestBatchAttemptHistory({
    method,
    attemptCount,
    actualStatus,
    checkState,
    timeout = 10000,
  }) {
    const history = page.locator(`#requestBatchSummary [data-batch-method="${method}"] details.request-batch-summary__history`);
    await history.waitFor({ state: "attached", timeout });
    const isOpen = await history.evaluate((node) => node.open);
    if (!isOpen) {
      await history.locator("summary").click();
    }

    await waitForPageCondition(
      `assertRequestBatchAttemptHistory(${method},${attemptCount})`,
      ([targetMethod, targetAttemptCount, targetActualStatus, targetCheckState]) => {
        const rows = Array.from(document.querySelectorAll("#requestBatchSummary [data-batch-method]"));
        const row = rows.find((item) => item.dataset.batchMethod === targetMethod);
        const details = row?.querySelector("details.request-batch-summary__history");
        const items = Array.from(row?.querySelectorAll("[data-batch-attempt-index]") || []);
        const rowText = row?.innerText || "";

        return Boolean(
          row &&
          details &&
          details.open &&
          details.dataset.batchAttemptHistory === targetMethod &&
          details.dataset.batchAttemptHistoryCount === targetAttemptCount &&
          (rowText.includes("История попыток") || rowText.includes("Attempt history")) &&
          items.length === Number(targetAttemptCount) &&
          items.every((item) => (
            item.dataset.batchAttemptActualStatus === targetActualStatus &&
            item.dataset.batchAttemptCheck === targetCheckState
          ))
        );
      },
      [method, String(attemptCount), actualStatus, checkState],
      timeout
    );
  }

  async function assertRequestBatchAttemptHistoryState({
    method,
    attemptCount,
    open,
    autoOpen,
    timeout = 10000,
  }) {
    await waitForPageCondition(
      `assertRequestBatchAttemptHistoryState(${method},${attemptCount},${open})`,
      ([targetMethod, targetAttemptCount, targetOpen, targetAutoOpen]) => {
        const row = Array.from(document.querySelectorAll("#requestBatchSummary [data-batch-method]"))
          .find((item) => item.dataset.batchMethod === targetMethod);
        const details = row?.querySelector("details.request-batch-summary__history");
        const items = Array.from(row?.querySelectorAll("[data-batch-attempt-index]") || []);

        return Boolean(
          row &&
          details &&
          details.open === targetOpen &&
          details.dataset.batchAttemptHistory === targetMethod &&
          details.dataset.batchAttemptHistoryCount === String(targetAttemptCount) &&
          details.dataset.batchAttemptHistoryOpen === String(targetAutoOpen) &&
          items.length === Number(targetAttemptCount)
        );
      },
      [method, attemptCount, open, autoOpen],
      timeout
    );

    const summary = page.locator(
      `#requestBatchSummary [data-batch-method="${method}"] details.request-batch-summary__history > summary`
    );
    const marker = await summary.evaluate((element) => {
      const before = getComputedStyle(element, "::before").content;
      const after = getComputedStyle(element, "::after").content;
      return {
        content: `${before} ${after}`,
        listStyleType: getComputedStyle(element).listStyleType,
      };
    });
    const accessibilityTree = await summary.ariaSnapshot();
    const expectedMarker = open ? "[-]" : "[+]";
    if (!marker.content.includes(expectedMarker) || marker.listStyleType !== "none") {
      throw new Error(
        `Request attempt history marker contract failed (${method}, ${expectedMarker}): ` +
        `${JSON.stringify(marker)}`
      );
    }
    if (/[▸▾▶▼]|\[\+\]|\[-\]/.test(accessibilityTree)) {
      throw new Error(`Request attempt history accessible name contains marker: ${accessibilityTree}`);
    }
  }

  async function injectRequestBatchMismatch({
    method,
    path,
    status,
    statusText,
    attemptCount,
    rerunOutcome,
    timeout = 10000,
  }) {
    await page.evaluate(([targetMethod, targetPath, targetStatus, targetStatusText]) => {
      window.XferryApp.invoke(
        "requests",
        "record-batch-result",
        targetMethod,
        targetPath,
        {
          kind: "response",
          status: targetStatus,
          statusText: targetStatusText,
        }
      );
    }, [method, path, status, statusText]);

    await assertRequestBatchRow({
      method,
      path,
      expectedStatus: "200 OK",
      actualStatus: `${status} ${statusText}`,
      checkState: "mismatch",
      attemptCount,
      rerunOutcome,
      rerunOutcomeTone: "danger",
      timeout,
    });
  }

  async function assertRequestPanelMethodOrder(expectedMethods, timeout = 10000) {
    await waitForPageCondition(
      "request panel method order",
      ([targetMethods]) => {
        const buttons = Array.from(document.querySelectorAll(".request-method-switch [data-request-method]"));
        return (
          buttons.length === targetMethods.length &&
          buttons.every((button, index) => {
            const method = button.dataset.requestMethod || "";
            const text = (button.textContent || "").trim();
            return method === targetMethods[index] && text === targetMethods[index];
          })
        );
      },
      [expectedMethods],
      timeout
    );
  }

  async function runRequestPanelMethodScenario({
    method,
    initialPath = "/",
    expectedRequestPath,
    expectedPathInput,
    expectedStatus,
    responseIncludes = [],
    previewIncludes = [],
    timeout = 15000,
  }) {
    await page.locator("#pathInput").fill(initialPath);
    await triggerRequestMethod(method);
    await waitForRequestPanelResponse(method, expectedStatus, expectedRequestPath, timeout);

    if (expectedPathInput) {
      await waitForValue("#pathInput", expectedPathInput, timeout);
    }

    const responseText = (await page.locator("#responseArea").innerText()).trim();
    for (const expectedText of responseIncludes) {
      if (!responseText.includes(expectedText)) {
        throw new Error(`Request panel ${method} response missing "${expectedText}": ${responseText}`);
      }
    }

    await waitForRequestPreview(method, expectedRequestPath, timeout);
    const previewText = (await page.locator("#requestPreviewArea").innerText()).trim();
    for (const expectedText of [`${method} ${expectedRequestPath} HTTP/1.1`, ...previewIncludes]) {
      if (!previewText.includes(expectedText)) {
        throw new Error(`Request panel ${method} preview missing "${expectedText}": ${previewText}`);
      }
    }

    await waitForLiveRegionText("responseAreaLive", `${method} ${expectedRequestPath} ${expectedStatus}`, timeout);

    return responseText;
  }

  async function triggerRequestMethod(method) {
    const locator = page.locator(`.request-method-switch [data-request-method="${method}"]`).first();
    if (!(await locator.isVisible())) {
      const state = await page.evaluate(() => ({
        hash: window.location.hash,
        activeTab: document.querySelector('[role="tab"][aria-selected="true"]')?.id || "",
        technicalOpen: document.getElementById("requestTechnicalDetails")?.open === true,
      }));
      throw new Error(`Request method ${method} is not visible: ${JSON.stringify(state)}`);
    }
    await locator.click();
  }

  async function assertRequestPanelScenarioMatrix() {
    const expectedMethods = [
      "GET",
      "HEAD",
      "OPTIONS",
      "FETCH",
      "INFO",
      "PING",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "NONE",
      "NOTE",
      "SMUGGLE",
    ];
    await assertRequestPanelMethodOrder(expectedMethods);
    await assertRequestTechnicalDetailsReachable(expectedMethods);
    await assertRequestPreviewVisibility(true);
    await assertRequestPreviewModeState("raw");
    await assertResponseViewState("raw");
    await waitForPageCondition(
      "request batch export initially disabled",
      () => {
        const exportBtn = document.getElementById("requestBatchExportBtn");
        const clearBtn = document.getElementById("requestBatchClearBtn");
        return Boolean(exportBtn && exportBtn.disabled && clearBtn && clearBtn.disabled);
      },
      null,
      10000
    );
    await assertRequestBatchIssuesFilter({
      checked: false,
      filter: "all",
      visibleCount: 0,
      emptyText: "",
      timeout: 10000,
    });
    await assertRequestPreviewVisibility(true);
    await assertRequestPreviewModeState("raw");
    await assertResponseViewState("raw");
    await waitForText(page.locator("#requestPreviewArea"), /Выберите метод|Choose a method/, 10000);
    await page.reload({ waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await assertRequestPreviewVisibility(true);
    await assertRequestPreviewModeState("raw");
    await assertResponseViewState("raw");
    await waitForText(page.locator("#requestPreviewArea"), /Выберите метод|Choose a method/, 10000);
    await openRequestTechnicalDetails({ includeBatch: true });
    await page.locator('[data-request-preview-mode="summary"]').click();
    await assertRequestPreviewModeState("summary");
    await assertResponseViewState("summary");
    await page.reload({ waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await assertRequestPreviewVisibility(true);
    await assertRequestPreviewModeState("summary");
    await assertResponseViewState("summary");
    await openRequestTechnicalDetails({ includeBatch: true });
    await page.locator("#pathInput").fill("/index.html");
    await triggerRequestMethod("GET");
    await waitForRequestPanelResponse("GET", 200, "/index.html", 15000);
    await waitForRequestPreview("GET", "/index.html", 15000);
    await assertRequestPreviewSummary("GET", "/index.html", ["GET", "/index.html", "Host", "200 OK"], 15000);
    await assertResponseSummary("GET", "/index.html", ["GET", "/index.html", "200 OK"], 15000);
    await page.locator("#requestPreviewCopyBtn").click();
    await assertClipboardSnapshot("request", ["GET /index.html HTTP/1.1", "Host:"], 15000);
    await page.locator("#responseCopyBtn").click();
    await assertClipboardSnapshot("response", ["HTTP/1.1 200 OK", "cache-control:", "<!DOCTYPE html>"], 15000);
    await assertRequestPreviewComparison({
      method: "GET",
      path: "/index.html",
      expectedStatus: "200 OK",
      actualStatus: "200 OK",
      checkState: "match",
      timeout: 15000,
    });
    await page.locator('[data-request-preview-mode="raw"]').click();
    await assertRequestPreviewModeState("raw");
    await assertResponseViewState("raw");
    await assertResponseRaw("GET", "/index.html", ["HTTP/1.1 200 OK", "cache-control:", "<!DOCTYPE html>"], 15000);
    await page.locator('[data-request-preview-mode="summary"]').click();
    await assertRequestPreviewModeState("summary");
    await assertResponseViewState("summary");
    await assertResponseSummary("GET", "/index.html", ["GET", "/index.html", "200 OK"], 15000);
    await page.locator("#pathInput").fill("/ignored-post");
    await triggerRequestMethod("POST");
    await waitForRequestPanelResponse("POST", 201, "/", 15000);
    await waitForRequestPreview("POST", "/", 15000);
    await waitForValue("#pathInput", "/uploads/request-panel-post.txt", 15000);
    await assertRequestPreviewSummary("POST", "/", ["POST", "/", "201 Created"], 15000);
    await assertRequestPreviewComparison({
      method: "POST",
      path: "/",
      expectedStatus: "201 Created",
      actualStatus: "201 Created",
      checkState: "match",
      timeout: 15000,
    });
    const missingPath = "/missing-browser-smoke.txt";
    await page.locator("#pathInput").fill(missingPath);
    await triggerRequestMethod("GET");
    await waitForRequestPanelResponse("GET", 404, missingPath, 15000);
    await waitForRequestPreview("GET", missingPath, 15000);
    await assertRequestPreviewSummary("GET", missingPath, ["GET", missingPath, "404 Not Found"], 15000);
    await assertRequestPreviewComparison({
      method: "GET",
      path: missingPath,
      expectedStatus: "200 OK",
      actualStatus: "404 Not Found",
      checkState: "mismatch",
      timeout: 15000,
    });
    await page.locator("#requestRunAllBtn").click();
    await waitForRequestBatchSummary({
      phase: "complete",
      total: 13,
      completed: 13,
      matchCount: 13,
      mismatchCount: 0,
      failedCount: 0,
      timeout: 60000,
    });
    await assertRequestBatchRow({
      method: "POST",
      path: "/",
      expectedStatus: "201 Created",
      actualStatus: "201 Created",
      checkState: "match",
      timeout: 15000,
    });
    await assertRequestBatchRow({
      method: "OPTIONS",
      path: "/",
      expectedStatus: "204 No Content",
      actualStatus: "204 No Content",
      checkState: "match",
      timeout: 15000,
    });
    await assertRequestMethodButtonBatchState({
      method: "GET",
      checkState: "match",
      expectedStatus: "200 OK",
      actualStatus: "200 OK",
      timeout: 15000,
    });
    await assertRequestMethodButtonBatchState({
      method: "POST",
      checkState: "match",
      expectedStatus: "201 Created",
      actualStatus: "201 Created",
      timeout: 15000,
    });
    await assertRequestMethodButtonBatchState({
      method: "OPTIONS",
      checkState: "match",
      expectedStatus: "204 No Content",
      actualStatus: "204 No Content",
      timeout: 15000,
    });
    await assertRequestBatchExport({
      phase: "complete",
      total: 13,
      completed: 13,
      matchCount: 13,
      mismatchCount: 0,
      failedCount: 0,
      expectedMethods: ["GET", "POST", "OPTIONS", "SMUGGLE"],
      expectedAttemptCounts: {
        GET: 1,
        OPTIONS: 1,
      },
      timeout: 15000,
    });
    await assertRequestBatchRerunIssuesButtonState({
      disabled: true,
      issueCount: 0,
      timeout: 15000,
    });
    await injectRequestBatchMismatch({
      method: "GET",
      path: "/index.html",
      status: 404,
      statusText: "Not Found",
      attemptCount: 2,
      rerunOutcome: "regressed",
      timeout: 15000,
    });
    await waitForRequestBatchSummary({
      phase: "complete",
      total: 13,
      completed: 13,
      matchCount: 12,
      mismatchCount: 1,
      failedCount: 0,
      timeout: 15000,
    });
    await assertRequestBatchAttemptHistoryState({
      method: "GET",
      attemptCount: 2,
      open: true,
      autoOpen: true,
      timeout: 15000,
    });
    await injectRequestBatchMismatch({
      method: "GET",
      path: "/index.html",
      status: 500,
      statusText: "Internal Server Error",
      attemptCount: 3,
      rerunOutcome: "still-failing",
      timeout: 15000,
    });
    await waitForRequestBatchSummary({
      phase: "complete",
      total: 13,
      completed: 13,
      matchCount: 12,
      mismatchCount: 1,
      failedCount: 0,
      timeout: 15000,
    });
    await assertRequestBatchAttemptHistoryState({
      method: "GET",
      attemptCount: 3,
      open: true,
      autoOpen: true,
      timeout: 15000,
    });
    await assertRequestMethodButtonBatchState({
      method: "GET",
      checkState: "mismatch",
      expectedStatus: "200 OK",
      actualStatus: "500 Internal Server Error",
      timeout: 15000,
    });
    await assertRequestBatchRerunIssuesButtonState({
      disabled: false,
      issueCount: 1,
      timeout: 15000,
    });
    await page.locator("#requestBatchRerunIssuesBtn").click();
    await waitForRequestPanelResponse("GET", 200, "/index.html", 15000);
    await waitForValue("#pathInput", "/index.html", 15000);
    await waitForRequestBatchSummary({
      phase: "complete",
      total: 13,
      completed: 13,
      matchCount: 13,
      mismatchCount: 0,
      failedCount: 0,
      timeout: 15000,
    });
    await assertRequestBatchRow({
      method: "GET",
      path: "/index.html",
      expectedStatus: "200 OK",
      actualStatus: "200 OK",
      checkState: "match",
      attemptCount: 4,
      rerunOutcome: "fixed",
      rerunOutcomeTone: "success",
      timeout: 15000,
    });
    await assertRequestBatchAttemptHistoryState({
      method: "GET",
      attemptCount: 4,
      open: false,
      autoOpen: false,
      timeout: 15000,
    });
    await assertRequestMethodButtonBatchState({
      method: "GET",
      checkState: "match",
      expectedStatus: "200 OK",
      actualStatus: "200 OK",
      timeout: 15000,
    });
    await assertRequestBatchRerunIssuesButtonState({
      disabled: true,
      issueCount: 0,
      timeout: 15000,
    });
    await page.locator("#requestBatchIssuesOnlyToggle").check();
    await assertRequestBatchIssuesFilter({
      checked: true,
      filter: "issues",
      visibleCount: 0,
      emptyText: "Все методы отработали без ошибок.",
      timeout: 15000,
    });
    await page.locator("#requestBatchIssuesOnlyToggle").uncheck();
    await assertRequestBatchIssuesFilter({
      checked: false,
      filter: "all",
      visibleCount: 13,
      emptyText: "",
      timeout: 15000,
    });
    await page.locator('#requestBatchSummary [data-batch-rerun-method="OPTIONS"]').click();
    await waitForRequestPanelResponse("OPTIONS", 204, "/", 15000);
    await waitForValue("#pathInput", "/", 15000);
    await assertRequestBatchRow({
      method: "OPTIONS",
      path: "/",
      expectedStatus: "204 No Content",
      actualStatus: "204 No Content",
      checkState: "match",
      attemptCount: 2,
      rerunOutcome: "still-ok",
      rerunOutcomeTone: "success",
      timeout: 15000,
    });
    await assertRequestBatchAttemptHistory({
      method: "OPTIONS",
      attemptCount: 2,
      actualStatus: "204 No Content",
      checkState: "match",
      timeout: 15000,
    });
    await assertRequestMethodButtonBatchState({
      method: "OPTIONS",
      checkState: "match",
      expectedStatus: "204 No Content",
      actualStatus: "204 No Content",
      timeout: 15000,
    });
    await assertRequestBatchExport({
      phase: "complete",
      total: 13,
      completed: 13,
      matchCount: 13,
      mismatchCount: 0,
      failedCount: 0,
      expectedMethods: ["GET", "OPTIONS"],
      expectedAttemptCounts: {
        GET: 4,
        OPTIONS: 2,
      },
      timeout: 15000,
    });
    await page.locator("#requestBatchClearBtn").click();
    await assertRequestBatchCleared(15000);
    await assertRequestBatchIssuesFilter({
      checked: false,
      filter: "all",
      visibleCount: 0,
      emptyText: "",
      timeout: 15000,
    });
    await page.locator('[data-request-preview-mode="raw"]').click();
    await assertRequestPreviewModeState("raw");
    await assertResponseViewState("raw");
    await page.reload({ waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await assertRequestPreviewVisibility(true);
    await assertRequestPreviewModeState("raw");
    await assertResponseViewState("raw");
    await assertRequestPreviewVisibility(true);
    await assertRequestPreviewModeState("raw");
    await assertResponseViewState("raw");
    await openRequestTechnicalDetails({ includeBatch: true });

    await runRequestPanelMethodScenario({
      method: "GET",
      initialPath: "/index.html",
      expectedRequestPath: "/index.html",
      expectedPathInput: "/index.html",
      expectedStatus: 200,
      responseIncludes: ["HTTP/1.1 200 OK", "<!DOCTYPE html>"],
      previewIncludes: ["Host:"],
    });

    await runRequestPanelMethodScenario({
      method: "HEAD",
      initialPath: "/index.html",
      expectedRequestPath: "/index.html",
      expectedPathInput: "/index.html",
      expectedStatus: 200,
      responseIncludes: ["HTTP/1.1 200 OK"],
      previewIncludes: ["Host:"],
    });

    await runRequestPanelMethodScenario({
      method: "POST",
      initialPath: "/ignored-post",
      expectedRequestPath: "/",
      expectedPathInput: "/uploads/request-panel-post.txt",
      expectedStatus: 201,
      responseIncludes: ['"path": "/uploads/request-panel-post.txt"'],
      previewIncludes: [
        "X-File-Name: request-panel-post.txt",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Length:",
        "request-panel demo via POST",
      ],
    });

    await runRequestPanelMethodScenario({
      method: "PUT",
      initialPath: "/ignored-put",
      expectedRequestPath: "/",
      expectedPathInput: "/uploads/request-panel-put.txt",
      expectedStatus: 201,
      responseIncludes: ['"path": "/uploads/request-panel-put.txt"'],
      previewIncludes: [
        "X-File-Name: request-panel-put.txt",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Length:",
        "request-panel demo via PUT",
      ],
    });

    await runRequestPanelMethodScenario({
      method: "PATCH",
      initialPath: "/ignored-patch",
      expectedRequestPath: "/",
      expectedPathInput: "/uploads/request-panel-patch.txt",
      expectedStatus: 201,
      responseIncludes: ['"path": "/uploads/request-panel-patch.txt"'],
      previewIncludes: [
        "X-File-Name: request-panel-patch.txt",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Length:",
        "request-panel demo via PATCH",
      ],
    });

    await runRequestPanelMethodScenario({
      method: "DELETE",
      initialPath: "/ignored-delete",
      expectedRequestPath: "/uploads/request-panel-delete.txt",
      expectedPathInput: "/uploads/request-panel-delete.txt",
      expectedStatus: 200,
      responseIncludes: [
        '"deleted_file"',
        '"name":"request-panel-delete.txt"',
        '"path":"/uploads/request-panel-delete.txt"',
      ],
    });

    await runRequestPanelMethodScenario({
      method: "OPTIONS",
      initialPath: "/ignored-options",
      expectedRequestPath: "/",
      expectedPathInput: "/",
      expectedStatus: 204,
      responseIncludes: ["HTTP/1.1 204 No Content"],
      previewIncludes: ["Access-Control-Request-Method: GET"],
    });

    await runRequestPanelMethodScenario({
      method: "INFO",
      initialPath: "/",
      expectedRequestPath: "/",
      expectedPathInput: "/",
      expectedStatus: 200,
      responseIncludes: [
        '"entry"',
        '"kind":"directory"',
        '"page"',
        '"contents"',
      ],
      previewIncludes: ["Host:"],
    });

    await runRequestPanelMethodScenario({
      method: "PING",
      initialPath: "/ignored-ping",
      expectedRequestPath: "/",
      expectedPathInput: "/",
      expectedStatus: 200,
      responseIncludes: ['"health": "ready"'],
      previewIncludes: ["Host:"],
    });

    await runRequestPanelMethodScenario({
      method: "NONE",
      initialPath: "/ignored-none",
      expectedRequestPath: "/",
      expectedPathInput: "/uploads/request-panel-none.txt",
      expectedStatus: 201,
      responseIncludes: ['"path": "/uploads/request-panel-none.txt"'],
      previewIncludes: [
        "X-File-Name: request-panel-none.txt",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Length:",
        "request-panel demo via NONE",
      ],
    });

    await runRequestPanelMethodScenario({
      method: "NOTE",
      initialPath: "/ignored-note",
      expectedRequestPath: "/notes/key",
      expectedPathInput: "/notes/key",
      expectedStatus: 200,
      responseIncludes: ['"key"', '"available":true'],
      previewIncludes: ["Host:"],
    });

    await runRequestPanelMethodScenario({
      method: "SMUGGLE",
      initialPath: "/ignored-smuggle",
      expectedRequestPath: "/uploads/request-panel-smuggle.txt",
      expectedPathInput: "/uploads/request-panel-smuggle.txt",
      expectedStatus: 200,
      responseIncludes: ['"artifact"', '"url":"/uploads/smuggle_'],
    });

    const fetchPath = "/uploads/request-panel-fetch.txt";
    await runRequestPanelMethodScenario({
      method: "FETCH",
      initialPath: "/ignored-fetch",
      expectedRequestPath: fetchPath,
      expectedPathInput: fetchPath,
      expectedStatus: 200,
      responseIncludes: ["HTTP/1.1 200 OK"],
    });

    const downloadButton = page.locator("#responseArea [data-download-path]");
    await downloadButton.waitFor({ state: "attached", timeout: 10000 });

    const fetchFileName = "request-panel-fetch.txt";
    const downloadPromise = page.waitForEvent("download");
    await downloadButton.click();
    await waitForPageCondition(
      `request-panel download progress mounted (${fetchFileName})`,
      ([targetName]) => {
        const progressArea = document.getElementById("downloadProgressArea");
        const progressText = document.getElementById("dlProgressText");
        return Boolean(progressArea && progressText && progressArea.innerText.includes(targetName));
      },
      [fetchFileName],
      10000
    );
    const download = await downloadPromise;
    const suggestedFilename = download.suggestedFilename();
    if (suggestedFilename !== fetchFileName) {
      throw new Error(`Request-panel FETCH download filename mismatch: ${suggestedFilename}`);
    }

    return fetchPath;
  }

  async function fetchViaRequestPanelAndAssert() {
    return assertRequestPanelScenarioMatrix();
  }

  async function getServerFileAction(name, action) {
    const encodedPath = encodeURIComponent(`/uploads/${name}`);
    const row = page.locator("#serverFiles .uploaded-file--file", {
      has: page.locator(".file-name", { hasText: name }),
    }).first();
    await row.waitFor({ state: "visible", timeout: 10000 });
    const actionButton = row.locator(
      `[data-file-action="${action}"][data-path="${encodedPath}"]`
    ).first();
    await actionButton.waitFor({ state: "attached", timeout: 10000 });
    if (action !== "download" && !await actionButton.isVisible()) {
      const disclosure = row.locator(".file-row__more");
      await disclosure.locator(":scope > summary").click();
      await actionButton.waitFor({ state: "visible", timeout: 10000 });
    }
    await actionButton.waitFor({ state: "visible", timeout: 10000 });
    return actionButton;
  }

  async function getServerFileDetailsTrigger(name, basePath = "/uploads") {
    const normalizedBase = basePath === "/" ? "" : String(basePath || "").replace(/\/$/, "");
    const encodedPath = encodeURIComponent(`${normalizedBase}/${name}`);
    const trigger = page.locator(
      `#serverFiles [data-file-details-trigger][data-path="${encodedPath}"]`
    ).first();
    await trigger.waitFor({ state: "visible", timeout: 10000 });
    return trigger;
  }

  async function fetchViaServerFilesAndAssert(name) {
    const actionButton = await getServerFileAction(name, "download");
    await actionButton.waitFor({ state: "visible", timeout: 10000 });

    const downloadPromise = page.waitForEvent("download");
    await actionButton.click();
    await waitForPageCondition(
      `server-files download progress mounted (${name})`,
      ([targetName]) => {
        const progressArea = document.getElementById("downloadProgressArea");
        const progressText = document.getElementById("dlProgressText");
        return Boolean(progressArea && progressText && progressArea.innerText.includes(targetName));
      },
      [name],
      10000
    );
    const download = await downloadPromise;
    const suggestedFilename = download.suggestedFilename();
    if (suggestedFilename !== name) {
      throw new Error(`Server-files FETCH download filename mismatch: ${suggestedFilename}`);
    }
  }

  async function assertFetchDownloadFilenameResolution(unicodeFilename) {
    const headerResolution = await page.evaluate((filename) => {
      const resolve = (headers, path) => window.XferryApp.invoke(
        "requests",
        "resolve-download-filename",
        headers,
        path
      );
      return {
        filenameStar: resolve({
          "Content-Disposition": `attachment; filename="fallback.bin"; filename*=UTF-8''${encodeURIComponent(filename)}`,
          "X-File-Name": "wrong-fallback.bin",
        }, "/uploads/download.bin"),
        urlFallback: resolve({ "X-File-Name": "wrong-fallback.bin" }, "/uploads/actual%20name.bin"),
        defaultFallback: resolve({}, "/uploads/actual.bin"),
      };
    }, unicodeFilename);
    if (
      headerResolution.filenameStar !== unicodeFilename ||
      headerResolution.urlFallback !== "actual name.bin" ||
      headerResolution.defaultFallback !== "actual.bin"
    ) {
      throw new Error(
        `FETCH download filename precedence failed: ${JSON.stringify(headerResolution)}`
      );
    }

    await browseUploadsAndAssert(unicodeFilename);
    await fetchViaServerFilesAndAssert(unicodeFilename);
    return headerResolution;
  }

  async function assertFileActionAccessibleNames(name) {
    const encodedPath = encodeURIComponent(`/uploads/${name}`);
    const actions = [
      { action: "download", prefix: /Download files|Скачивание файлов/i },
      { action: "smuggle", prefix: /HTML smuggling/i },
      { action: "delete", prefix: /Delete|Удалить/i },
    ];

    for (const { action, prefix } of actions) {
      const button = await getServerFileAction(name, action);
      const ariaLabel = (await button.getAttribute("aria-label")) || "";
      if (!prefix.test(ariaLabel) || !ariaLabel.includes(name)) {
        throw new Error(`Unexpected accessible name for ${action}: ${ariaLabel}`);
      }
    }

    const detailsTrigger = await getServerFileDetailsTrigger(name);
    const detailsLabel = (await detailsTrigger.getAttribute("aria-label")) || "";
    if (
      !/Show file details|Показать сведения о файле/i.test(detailsLabel) ||
      !detailsLabel.includes(name) ||
      (await detailsTrigger.getAttribute("aria-expanded")) !== "false" ||
      !(await detailsTrigger.getAttribute("aria-controls"))
    ) {
      throw new Error(`Unexpected accessible name/state for file details trigger: ${detailsLabel}`);
    }

    const removedInfoActions = await page.locator(
      `#serverFiles [data-file-action][data-path="${encodedPath}"]`
    ).evaluateAll(actions => actions.filter(action => action.dataset.fileAction === "info").length);
    if (removedInfoActions !== 0) {
      throw new Error(`Legacy metadata menu action is still rendered for ${name}`);
    }
  }

  async function assertFileDisclosureInteractions(firstName, secondName) {
    const disclosureFor = (name) => {
      const encodedPath = encodeURIComponent(`/uploads/${name}`);
      return page.locator(
        `#serverFiles [data-file-action="smuggle"][data-path="${encodedPath}"]`
      ).first().locator("xpath=ancestor::details[1]");
    };
    const first = disclosureFor(firstName);
    const second = disclosureFor(secondName);
    const firstSummary = first.locator(":scope > summary");
    const secondSummary = second.locator(":scope > summary");
    const firstTrigger = await getServerFileDetailsTrigger(firstName);
    const firstEncodedPath = encodeURIComponent(`/uploads/${firstName}`);
    const firstSelect = page.locator(
      `#serverFiles [data-file-select][data-path="${firstEncodedPath}"]`
    );

    if (await firstSelect.count()) {
      await firstSelect.check();
      if ((await firstTrigger.getAttribute("aria-expanded")) !== "false") {
        throw new Error("Selecting a file toggled inline details");
      }
      await firstSelect.uncheck();
    }

    await firstSummary.click();
    await waitForPageCondition(
      "first file disclosure opens alone",
      ([targetPath]) => Boolean(
        document.querySelectorAll("#serverFiles .file-row__more[open]").length === 1 &&
        document.querySelector(`#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`)
          ?.getAttribute("aria-expanded") === "false"
      ),
      [firstEncodedPath]
    );
    await secondSummary.click();
    await waitForPageCondition(
      "opening another file disclosure closes the first",
      ([targetName]) => {
        const open = Array.from(document.querySelectorAll("#serverFiles .file-row__more[open]"));
        return open.length === 1 && open[0].querySelector("summary")?.getAttribute("aria-label")?.includes(targetName);
      },
      [secondName]
    );

    const secondSmuggleAction = second.locator('[data-file-action="smuggle"]');
    await secondSmuggleAction.focus();
    await waitForPageCondition(
      "file disclosure child action receives focus",
      ([targetName]) => (
        document.activeElement?.getAttribute("data-file-action") === "smuggle" &&
        document.activeElement?.getAttribute("aria-label")?.includes(targetName)
      ),
      [secondName]
    );
    await page.keyboard.press("Escape");
    await waitForPageCondition(
      "Escape closes file disclosure and keeps summary focus",
      ([targetName]) => (
        document.querySelectorAll("#serverFiles .file-row__more[open]").length === 0 &&
        document.activeElement?.matches(".file-row__more > summary") &&
        document.activeElement?.getAttribute("aria-label")?.includes(targetName)
      ),
      [secondName]
    );

    await firstSummary.click();
    const secondEncodedPath = encodeURIComponent(`/uploads/${secondName}`);
    const secondSelect = page.locator(
      `#serverFiles [data-file-select][data-path="${secondEncodedPath}"]`
    );
    if (await secondSelect.count()) {
      await secondSelect.check();
      await secondSelect.uncheck();
    } else {
      await page.locator("#browsePathInput").click();
    }
    await waitForPageCondition(
      "clicking another row control closes the open file disclosure without details",
      ([targetPath]) => (
        document.querySelectorAll("#serverFiles .file-row__more[open]").length === 0 &&
        document.querySelector(`#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`)
          ?.getAttribute("aria-expanded") === "false"
      ),
      [secondEncodedPath]
    );

    await firstSummary.click();
    await page.locator("#browsePathInput").click();
    await waitForPageCondition(
      "clicking outside the file list closes the open disclosure",
      () => document.querySelectorAll("#serverFiles .file-row__more[open]").length === 0
    );
  }

  async function chooseSmuggleCombobox(id, value, expectedCanonical = value) {
    const input = page.locator(`#${id}`);
    await input.fill(value);
    await input.press("Enter");
    await waitForPageCondition(
      `smuggle combobox ${id} committed ${value}`,
      ([controlId, expectedValue]) => (
        document.getElementById(`${controlId}Value`)?.value === expectedValue &&
        document.getElementById(controlId)?.getAttribute("aria-invalid") !== "true"
      ),
      [id, expectedCanonical]
    );
  }

  async function assertSmuggleSearchableComboboxContract(name) {
    const actionButton = await getServerFileAction(name, "smuggle");
    await actionButton.click();
    const modal = page.locator("#smuggleModal");
    await modal.waitFor({ state: "attached", timeout: 10000 });

    const structure = await page.evaluate(() => {
      const ids = [
        "smuggleDownloadExt",
        "smugglePreset",
        "smuggleEncryption",
        "smugglePayloadEncoding",
        "smuggleTriggerMethod",
        "smuggleTriggerEvent",
        "smuggleOutputFormat",
        "smuggleDownloadVariant",
        "smugglePageTemplate",
        "smuggleMimeType",
      ];
      return {
        valid: ids.every((id) => {
          const input = document.getElementById(id);
          const listbox = document.getElementById(`${id}Listbox`);
          return Boolean(
            input?.getAttribute("role") === "combobox" &&
            input.getAttribute("aria-autocomplete") === "list" &&
            input.getAttribute("aria-expanded") === "false" &&
            input.getAttribute("aria-controls") === `${id}Listbox` &&
            !input.hasAttribute("aria-activedescendant") &&
            listbox?.getAttribute("role") === "listbox" &&
            document.getElementById(`${id}Value`)
          );
        }),
        mimeInputs: document.querySelectorAll("#smuggleModal #smuggleMimeType").length,
        nativeSelects: document.querySelectorAll('#smuggleModal select[id^="smuggle"]').length,
      };
    });
    if (!structure.valid || structure.mimeInputs !== 1 || structure.nativeSelects !== 0) {
      throw new Error(`SMUGGLE combobox structure failed: ${JSON.stringify(structure)}`);
    }

    const preset = page.locator("#smugglePreset");
    await preset.click();
    await waitForPageCondition(
      `smuggle preset opens with every advertised choice (${name})`,
      () => {
        const options = Array.from(
          document.querySelectorAll("#smugglePresetListbox [role='option']:not([aria-disabled='true'])")
        ).map((option) => option.textContent || "");
        return (
          document.getElementById("smugglePreset")?.getAttribute("aria-expanded") === "true" &&
          options.some((label) => label.includes("direct")) &&
          options.some((label) => label.includes("card_manual")) &&
          options.some((label) => label.includes("card_auto"))
        );
      }
    );
    await preset.press("Escape");

    const extension = page.locator("#smuggleDownloadExt");
    await extension.fill("df");
    await waitForPageCondition(
      `smuggle extension substring filtering (${name})`,
      () => {
        const input = document.getElementById("smuggleDownloadExt");
        const options = Array.from(document.querySelectorAll("#smuggleDownloadExtListbox [role='option']:not([aria-disabled='true'])"));
        return Boolean(
          document.activeElement === input &&
          input?.getAttribute("aria-expanded") === "true" &&
          options.length > 0 && options.length <= 8 &&
          options.some(option => (option.textContent || "").includes(".pdf"))
        );
      }
    );
    await extension.press("ArrowDown");
    await waitForPageCondition(
      `smuggle combobox active descendant keeps input focus (${name})`,
      () => {
        const input = document.getElementById("smuggleDownloadExt");
        const activeId = input?.getAttribute("aria-activedescendant") || "";
        return document.activeElement === input && Boolean(activeId && document.getElementById(activeId));
      }
    );
    await extension.press("Enter");
    await waitForPageCondition(
      `smuggle combobox Enter selects filtered option (${name})`,
      () => (
        document.getElementById("smuggleDownloadExtValue")?.value === "pdf" &&
        document.getElementById("smuggleDownloadExt")?.getAttribute("aria-expanded") === "false"
      )
    );

    await chooseSmuggleCombobox("smuggleDownloadExt", ".tar+gz.part", "tar+gz.part");
    await waitForPageCondition(
      `smuggle custom compound extension preview (${name})`,
      () => (
        document.getElementById("smuggleDownloadExtValue")?.dataset.custom === "true" &&
        (document.getElementById("smuggleDownloadNamePreview")?.textContent || "").endsWith(".tar+gz.part")
      )
    );

    await extension.fill("safe.-part");
    await page.locator("#smuggleDialogTitle").click();
    await waitForPageCondition(
      `smuggle custom extension segment must start alphanumeric (${name})`,
      () => (
        document.getElementById("smuggleDownloadExtValue")?.value === "" &&
        document.getElementById("smuggleDownloadExt")?.getAttribute("aria-invalid") === "true"
      )
    );
    await chooseSmuggleCombobox("smuggleDownloadExt", ".tar+gz.part", "tar+gz.part");

    await preset.fill("not-an-advertised-preset");
    await page.locator("#smuggleSubmitBtn").click();
    await waitForPageCondition(
      `smuggle constrained option error and retry focus (${name})`,
      () => (
        document.activeElement?.id === "smugglePreset" &&
        document.getElementById("smugglePreset")?.getAttribute("aria-invalid") === "true" &&
        document.getElementById("smugglePresetValue")?.value === "" &&
        document.getElementById("smugglePresetError")?.hidden === false &&
        document.getElementById("smuggleModal")?.dataset.smugglePhase === "editing"
      )
    );
    await preset.fill("direct");
    await waitForPageCondition(
      `smuggle field error clears on edit (${name})`,
      () => document.getElementById("smugglePreset")?.hasAttribute("aria-invalid") === false
    );
    await preset.press("Enter");

    await page.locator("#smuggleAdvancedSettings > summary").click();
    await page.locator("#smuggleConstructorEnabled").check();
    const triggerMethod = page.locator("#smuggleTriggerMethod");
    await triggerMethod.click();
    await waitForPageCondition(
      `smuggle trigger method exposes the complete advertised list (${name})`,
      () => {
        const labels = Array.from(
          document.querySelectorAll("#smuggleTriggerMethodListbox [role='option']:not([aria-disabled='true'])")
        ).map((option) => option.textContent || "");
        return (
          labels.length >= 20 &&
          labels.some((label) => label.includes("csstransition")) &&
          labels.some((label) => label.includes("script")) &&
          labels.some((label) => label.includes("form"))
        );
      }
    );
    await triggerMethod.press("Escape");

    const mimeType = page.locator("#smuggleMimeType");
    await mimeType.click();
    await waitForPageCondition(
      `smuggle MIME exposes the complete preset list (${name})`,
      () => {
        const labels = Array.from(
          document.querySelectorAll("#smuggleMimeTypeListbox [role='option']:not([aria-disabled='true'])")
        ).map((option) => option.textContent || "");
        return (
          labels.length >= 30 &&
          labels.some((label) => label.includes("application/pdf")) &&
          labels.some((label) => label.includes("application/vnd.microsoft.portable-executable")) &&
          labels.some((label) => label.includes("application/x-powershell"))
        );
      }
    );
    await mimeType.press("Escape");

    const payloadEncoding = page.locator("#smugglePayloadEncoding");
    await payloadEncoding.fill("url-safe");
    await payloadEncoding.press("ArrowDown");
    await payloadEncoding.press("Enter");
    await waitForPageCondition(
      `smuggle keyword filtering selects payload encoding (${name})`,
      () => document.getElementById("smugglePayloadEncodingValue")?.value === "base64url"
    );
    await chooseSmuggleCombobox("smuggleTriggerMethod", "button");
    await waitForPageCondition(
      `smuggle trigger event resets for method (${name})`,
      () => document.getElementById("smuggleTriggerEventValue")?.value === "onfocus"
    );
    await chooseSmuggleCombobox("smuggleTriggerEvent", "user-ready", "onuser-ready");
    await waitForPageCondition(
      `smuggle custom trigger warning (${name})`,
      () => {
        const warning = document.getElementById("smuggleCompatibilityList")?.textContent || "";
        return Boolean(
          document.getElementById("smuggleTriggerEventValue")?.dataset.custom === "true" &&
          (/synthetic dispatch/i.test(warning) || /синтетическ/i.test(warning))
        );
      }
    );
    await chooseSmuggleCombobox("smuggleTriggerMethod", "svg");
    await waitForPageCondition(
      `smuggle stale custom event resets on method change (${name})`,
      () => (
        document.getElementById("smuggleTriggerEventValue")?.value === "onload" &&
        document.getElementById("smuggleTriggerEventValue")?.dataset.custom === "false"
      )
    );
    await triggerMethod.fill("pageshow");
    await page.locator("#smuggleModeTitle").click();
    await waitForPageCondition(
      `smuggle removed trigger method alias is rejected (${name})`,
      () => (
        document.getElementById("smuggleTriggerMethodValue")?.value === "" &&
        document.getElementById("smuggleTriggerMethod")?.getAttribute("aria-invalid") === "true"
      )
    );
    await chooseSmuggleCombobox("smuggleTriggerMethod", "body");
    await chooseSmuggleCombobox("smuggleTriggerEvent", "onpageshow");
    await chooseSmuggleCombobox("smuggleTriggerMethod", "svg");

    const customMime = "Application/X-Acme; Profile=CaseSensitive";
    await chooseSmuggleCombobox("smuggleMimeType", customMime);
    await page.locator("#smuggleConstructorEnabled").uncheck();
    await page.locator("#smuggleConstructorEnabled").check();
    await waitForPageCondition(
      `smuggle custom MIME survives constructor toggle (${name})`,
      ([expectedMime]) => (
        document.getElementById("smuggleMimeType")?.value === expectedMime &&
        document.getElementById("smuggleMimeTypeValue")?.value === expectedMime &&
        document.getElementById("smuggleMimeType")?.disabled === false
      ),
      [customMime]
    );

    const output = page.locator("#smuggleOutputFormat");
    await output.focus();
    await output.press("ArrowDown");
    await output.press("Escape");
    await waitForPageCondition(
      `smuggle Escape closes listbox without closing dialog (${name})`,
      () => (
        document.getElementById("smuggleModal") &&
        document.getElementById("smuggleOutputFormat")?.getAttribute("aria-expanded") === "false" &&
        document.activeElement?.id === "smuggleOutputFormat"
      )
    );
    await output.press("ArrowDown");
    await output.press("Tab");
    await waitForPageCondition(
      `smuggle Tab commits and advances (${name})`,
      () => (
        document.getElementById("smuggleOutputFormat")?.getAttribute("aria-expanded") === "false" &&
        document.activeElement?.id === "smuggleDownloadVariant"
      )
    );
    await page.locator("#smuggleDownloadVariant").click();
    await page.locator("#smuggleModeTitle").click();
    await waitForPageCondition(
      `smuggle outside click closes listbox (${name})`,
      () => document.getElementById("smuggleDownloadVariant")?.getAttribute("aria-expanded") === "false"
    );

    await page.locator("#smuggleCancelBtn").click();
    await modal.waitFor({ state: "detached", timeout: 10000 });
    await page.evaluate(() => new Promise(resolve => {
      requestAnimationFrame(() => requestAnimationFrame(resolve));
    }));
  }

  async function assertSmuggleReservedEncodingAndModeState(name) {
    const actionButton = await getServerFileAction(name, "smuggle");
    const originalEncodedPath = await actionButton.getAttribute("data-path");
    const reservedSourcePath = "/uploads/Folder #?%/Payload %23 #?%.bin";
    const reservedEncodedDataPath = encodeURIComponent(reservedSourcePath);
    const expectedEncodedPath = "/uploads/Folder%20%23%3F%25/Payload%20%2523%20%23%3F%25.bin";
    const reservedDownloadName = "Report #?%  Final";
    const modal = page.locator("#smuggleModal");

    await actionButton.evaluate((button, encodedPath) => {
      button.dataset.path = encodedPath;
    }, reservedEncodedDataPath);
    const reservedActionButton = page.locator(
      `#serverFiles [data-file-action="smuggle"][data-path="${reservedEncodedDataPath}"]`
    ).first();
    await page.evaluate((targetPath) => {
      const http = window.XferryApp.service("http");
      let originalAdapter = null;
      const reservedInfoAdapter = (method, url, ...args) => {
        const pathname = decodeURIComponent(new URL(String(url), location.href).pathname);
        if (String(method).toUpperCase() === "INFO" && pathname === targetPath) {
          return Promise.resolve(new Response(JSON.stringify({ entry: {
            name: targetPath.split("/").pop(),
            path: targetPath,
            kind: "file",
            size_bytes: 1,
            size_human: "1 B",
            content_type: "application/octet-stream",
          } }), {
            status: 200,
            statusText: "OK",
            headers: { "Content-Type": "application/json" },
          }));
        }
        return originalAdapter(method, url, ...args);
      };
      originalAdapter = http["set-adapter"](reservedInfoAdapter);
      window.__smuggleReservedInfoOriginalAdapter = originalAdapter;
    }, reservedSourcePath);

    try {
      await reservedActionButton.click();
      await modal.waitFor({ state: "attached", timeout: 10000 });
      await waitForPageCondition(
        `smuggle simple screen stays focused (${name})`,
        () => {
          const modalNode = document.getElementById("smuggleModal");
          const advanced = document.getElementById("smuggleAdvancedSettings");
          const pageSettings = document.getElementById("smugglePageSettings");
          const summary = document.getElementById("smuggleSummary");
          const technicalDetails = document.getElementById("smuggleTechnicalDetails");
          const constructor = document.getElementById("smuggleConstructorEnabled");
          const text = modalNode?.textContent || "";
          return Boolean(
            advanced && !advanced.open &&
            pageSettings && !pageSettings.open &&
            !summary &&
            !technicalDetails &&
            constructor && !constructor.checkVisibility() &&
            !document.getElementById("smugglePreview") &&
            !text.includes("Пайплайн") && !text.includes("Pipeline") &&
            !text.includes("Внешний вид") && !text.includes("Appearance")
          );
        },
        null,
        10000
      );
      await page.locator("#smuggleDownloadName").fill(reservedDownloadName);
      await chooseSmuggleCombobox("smuggleDownloadExt", "pdf");
      await page.locator("#smuggleAdvancedSettings > summary").click();

      await waitForPageCondition(
        `smuggle reserved filename/path encoding (${name})`,
        ([targetPath, targetDownloadParam]) => {
          const params = new URLSearchParams();
          const downloadName = document.getElementById("smuggleDownloadName")?.value?.trim() || "";
          const downloadExt = document.getElementById("smuggleDownloadExtValue")?.value || "";
          const preset = document.getElementById("smugglePresetValue")?.value || "direct";
          const title = document.getElementById("smuggleTitleInput")?.value?.trim() || "";
          const message = document.getElementById("smuggleMessageInput")?.value?.trim() || "";
          const ctaLabel = document.getElementById("smuggleCtaLabelInput")?.value?.trim() || "";
          const delayMs = document.getElementById("smuggleDelayMs")?.value || "";
          const showNotice = document.getElementById("smuggleShowNotice")?.checked !== false;
          const locale = document.documentElement.lang.toLowerCase().startsWith("en") ? "en" : "ru";
          if (downloadName) params.set("download_name", downloadName);
          params.set("download_ext", downloadExt);
          params.set("preset", preset);
          if (title) params.set("title", title);
          if (message) params.set("message", message);
          if ((preset === "card_manual" || preset === "card_auto") && ctaLabel) {
            params.set("cta_label", ctaLabel);
          }
          if (preset === "card_auto") {
            params.set("delay_ms", delayMs);
          }
          params.set("show_notice", showNotice ? "1" : "0");
          params.set("locale", locale);
          const requestPath = `${targetPath}?${params.toString()}`;
          const curl = requestPath
            ? new URL(requestPath, window.location.href).toString()
            : "";
          const normalizedName = document.getElementById("smuggleDownloadNamePreview")?.textContent || "";
          return Boolean(
            requestPath.startsWith(`${targetPath}?`) &&
            requestPath.includes(targetDownloadParam) &&
            !requestPath.includes("/uploads%2F") &&
            !requestPath.includes("Payload%2520") &&
            curl.includes(targetPath) &&
            normalizedName === "Report-Final.pdf"
          );
        },
        [expectedEncodedPath, "download_name=Report+%23%3F%25++Final"],
        10000
      );

      await chooseSmuggleCombobox("smugglePreset", "card_auto");
      await chooseSmuggleCombobox("smuggleEncryption", "xor");
      await waitForPageCondition(
        `smuggle encryption is selectable in simple mode (${name})`,
        () => (
          document.getElementById("smuggleEncryptionValue")?.value === "xor" &&
          document.getElementById("smuggleEncryption")?.disabled === false &&
          document.getElementById("smuggleConstructorEnabled")?.checked === false
        ),
        null,
        10000
      );

      await page.locator("#smuggleConstructorEnabled").check();
      await waitForPageCondition(
        `smuggle encryption remains selectable in constructor mode (${name})`,
        () => {
          const simplePanel = document.querySelector('[data-smuggle-mode-panel="simple"]');
          const constructorPanel = document.querySelector('[data-smuggle-mode-panel="constructor"]');
          return Boolean(
            document.getElementById("smuggleEncryptionValue")?.value === "xor" &&
            document.getElementById("smuggleEncryption")?.disabled === false &&
            document.getElementById("smuggleConstructorEnabled")?.checked &&
            simplePanel?.hidden &&
            constructorPanel && !constructorPanel.hidden
          );
        },
        null,
        10000
      );

      await chooseSmuggleCombobox("smuggleEncryption", "aes");
      await chooseSmuggleCombobox("smugglePayloadEncoding", "hex");
      await chooseSmuggleCombobox("smuggleOutputFormat", "svg");
      await page.locator("#smuggleConstructorEnabled").uncheck();
      await waitForPageCondition(
        `smuggle simple state retains selected encryption (${name})`,
        () => {
          const constructorToggle = document.getElementById("smuggleConstructorEnabled");
          const payload = document.getElementById("smugglePayloadEncoding");
          const output = document.getElementById("smuggleOutputFormat");
          return Boolean(
            document.getElementById("smuggleEncryptionValue")?.value === "aes" &&
            document.getElementById("smuggleEncryption")?.disabled === false &&
            !constructorToggle?.checked &&
            payload?.value === "hex" && payload.disabled &&
            output?.value === "svg" && output.disabled
          );
        },
        null,
        10000
      );

      await page.locator("#smuggleConstructorEnabled").check();
      await waitForPageCondition(
        `smuggle constructor state retains selected encryption (${name})`,
        () => {
          const payload = document.getElementById("smugglePayloadEncoding");
          const output = document.getElementById("smuggleOutputFormat");
          return Boolean(
            document.getElementById("smuggleEncryptionValue")?.value === "aes" &&
            document.getElementById("smuggleEncryption")?.disabled === false &&
            payload?.value === "hex" && !payload.disabled &&
            output?.value === "svg" && !output.disabled
          );
        },
        null,
        10000
      );

      await page.locator("#smuggleCancelBtn").click();
      await modal.waitFor({ state: "detached", timeout: 10000 });
    } finally {
      await page.evaluate(() => {
        if (window.__smuggleReservedInfoOriginalAdapter) {
          window.XferryApp.service("http")["set-adapter"](
            window.__smuggleReservedInfoOriginalAdapter
          );
        }
        delete window.__smuggleReservedInfoOriginalAdapter;
      });
      if (await modal.count()) {
        await page.evaluate(() => {
          document.querySelector('#smuggleModal [data-dialog-action="cancel"]')?.click();
        });
        await modal.waitFor({ state: "detached", timeout: 10000 }).catch(() => {});
      }
      if (originalEncodedPath && await reservedActionButton.count()) {
        await reservedActionButton.evaluate((button, encodedPath) => {
          button.dataset.path = encodedPath;
        }, originalEncodedPath);
      }
    }
  }

  async function assertSmuggleMobileLayoutContract(name) {
    const actionButton = await getServerFileAction(name, "smuggle");
    await actionButton.click();

    const modal = page.locator("#smuggleModal");
    await modal.waitFor({ state: "attached", timeout: 10000 });
    await page.locator("#smuggleSubmitBtn").waitFor({ state: "visible", timeout: 10000 });

    const before = await page.evaluate(() => {
      const dialog = document.querySelector("#smuggleModal .smuggle-dialog");
      const overlay = document.querySelector("#smuggleModal .smuggle-modal-overlay");
      const header = dialog?.querySelector(".smuggle-dialog__header");
      const body = dialog?.querySelector(".smuggle-dialog__body");
      const footer = dialog?.querySelector(".smuggle-dialog__footer");
      const layout = dialog?.querySelector(".smuggle-dialog__layout");
      const main = dialog?.querySelector(".smuggle-dialog__main");
      const advanced = dialog?.querySelector("#smuggleAdvancedSettings");
      const pageSettings = dialog?.querySelector("#smugglePageSettings");
      if (!dialog || !overlay || !header || !body || !footer || !layout || !main || !advanced || !pageSettings) {
        return null;
      }
      body.scrollTop = 0;
      const dialogRect = dialog.getBoundingClientRect();
      const footerRect = footer.getBoundingClientRect();
      const mainRect = main.getBoundingClientRect();
      return {
        viewportWidth: window.innerWidth,
        viewportHeight: window.innerHeight,
        dialogLeft: dialogRect.left,
        dialogRight: dialogRect.right,
        dialogScrollWidth: dialog.scrollWidth,
        dialogClientWidth: dialog.clientWidth,
        documentOverflowY: getComputedStyle(document.body).overflowY,
        overlayOverflowY: getComputedStyle(overlay).overflowY,
        overlayScrollHeight: overlay.scrollHeight,
        overlayClientHeight: overlay.clientHeight,
        bodyOverflowY: getComputedStyle(body).overflowY,
        bodyScrollWidth: body.scrollWidth,
        bodyClientWidth: body.clientWidth,
        headerPosition: getComputedStyle(header).position,
        footerPosition: getComputedStyle(footer).position,
        footerTop: footerRect.top,
        footerBottom: footerRect.bottom,
        footerScrollWidth: footer.scrollWidth,
        footerClientWidth: footer.clientWidth,
        gridColumns: getComputedStyle(layout).gridTemplateColumns,
        mainLeft: mainRect.left,
        mainWidth: mainRect.width,
        advancedOpen: advanced.open,
        pageSettingsOpen: pageSettings.open,
        hasPreview: Boolean(dialog.querySelector("#smugglePreview")),
      };
    });

    await page.locator("#smuggleDownloadExt").click();
    const mobileCombobox = await page.evaluate(() => {
      const input = document.getElementById("smuggleDownloadExt");
      const listbox = document.getElementById("smuggleDownloadExtListbox");
      const option = listbox?.querySelector('[role="option"]');
      const inputRect = input?.getBoundingClientRect();
      const listRect = listbox?.getBoundingClientRect();
      const optionRect = option?.getBoundingClientRect();
      return {
        expanded: input?.getAttribute("aria-expanded") === "true",
        inputLeft: inputRect?.left ?? -1,
        inputRight: inputRect?.right ?? -1,
        listLeft: listRect?.left ?? -1,
        listRight: listRect?.right ?? -1,
        optionHeight: optionRect?.height ?? -1,
        listScrollWidth: listbox?.scrollWidth ?? -1,
        listClientWidth: listbox?.clientWidth ?? -1,
      };
    });
    await page.locator("#smuggleDownloadExtListbox [data-option-index]").first().click();
    await waitForPageCondition(
      `smuggle mobile pointer selection keeps input focus (${name})`,
      () => (
        Boolean(document.getElementById("smuggleDownloadExtValue")?.value) &&
        document.getElementById("smuggleDownloadExt")?.getAttribute("aria-expanded") === "false" &&
        document.activeElement?.id === "smuggleDownloadExt"
      )
    );

    await page.locator("#smuggleAdvancedSettings > summary").click();
    await page.locator("#smuggleConstructorEnabled").waitFor({ state: "visible", timeout: 10000 });
    await page.evaluate(() => {
      const body = document.querySelector("#smuggleModal .smuggle-dialog__body");
      if (body) body.scrollTop = body.scrollHeight;
    });
    const after = await page.evaluate(() => {
      const footer = document.querySelector("#smuggleModal .smuggle-dialog__footer");
      const body = document.querySelector("#smuggleModal .smuggle-dialog__body");
      const dialog = document.querySelector("#smuggleModal .smuggle-dialog");
      const footerRect = footer?.getBoundingClientRect();
      const dialogRect = dialog?.getBoundingClientRect();
      return {
        advancedOpen: document.getElementById("smuggleAdvancedSettings")?.open === true,
        bodyScrollable: Boolean(body && body.scrollHeight > body.clientHeight),
        bodyAtBottom: Boolean(body && body.scrollTop > 0 && body.scrollTop + body.clientHeight >= body.scrollHeight - 1),
        bodyScrollWidth: body?.scrollWidth ?? -1,
        bodyClientWidth: body?.clientWidth ?? -1,
        dialogLeft: dialogRect?.left ?? -1,
        dialogRight: dialogRect?.right ?? -1,
        footerTop: footerRect?.top ?? -1,
        footerBottom: footerRect?.bottom ?? -1,
      };
    });

    const valid = Boolean(
      before &&
      before.viewportWidth === 390 &&
      before.dialogLeft >= 0 &&
      before.dialogRight <= before.viewportWidth + 1 &&
      before.dialogScrollWidth <= before.dialogClientWidth + 1 &&
      before.documentOverflowY === "hidden" &&
      before.overlayOverflowY === "hidden" &&
      before.overlayScrollHeight <= before.overlayClientHeight + 1 &&
      before.bodyOverflowY === "auto" &&
      before.bodyScrollWidth <= before.bodyClientWidth + 1 &&
      before.headerPosition === "sticky" &&
      before.footerPosition === "sticky" &&
      before.footerTop >= 0 &&
      before.footerBottom <= before.viewportHeight + 1 &&
      before.footerScrollWidth <= before.footerClientWidth + 1 &&
      before.gridColumns.trim().split(/\s+/).length === 1 &&
      before.mainLeft >= before.dialogLeft &&
      before.mainWidth <= before.dialogClientWidth + 1 &&
      !before.advancedOpen && !before.pageSettingsOpen && !before.hasPreview &&
      mobileCombobox.expanded &&
      mobileCombobox.inputLeft >= 0 &&
      mobileCombobox.inputRight <= before.viewportWidth + 1 &&
      mobileCombobox.listLeft >= 0 &&
      mobileCombobox.listRight <= before.viewportWidth + 1 &&
      mobileCombobox.optionHeight >= 44 &&
      mobileCombobox.listScrollWidth <= mobileCombobox.listClientWidth + 1 &&
      after.advancedOpen &&
      after.bodyScrollable &&
      after.bodyAtBottom &&
      after.bodyScrollWidth <= after.bodyClientWidth + 1 &&
      after.dialogLeft >= 0 &&
      after.dialogRight <= before.viewportWidth + 1 &&
      after.footerTop >= 0 &&
      after.footerBottom <= before.viewportHeight + 1
    );
    if (!valid) {
      throw new Error(`SMUGGLE mobile sticky/no-overflow contract failed: ${JSON.stringify({ before, mobileCombobox, after })}`);
    }

    await page.locator("#smuggleCancelBtn").click();
    await modal.waitFor({ state: "detached", timeout: 10000 });
    return { before, mobileCombobox, after };
  }

  async function smuggleViaServerFilesAndAssert(name) {
    await assertSmuggleReservedEncodingAndModeState(name);
    const actionButton = await getServerFileAction(name, "smuggle");
    await actionButton.waitFor({ state: "visible", timeout: 10000 });
    await actionButton.click();

    const modal = page.locator("#smuggleModal");
    await modal.waitFor({ state: "attached", timeout: 10000 });
    await page.locator('#smuggleModal [role="dialog"]').waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smuggleDownloadName").waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smuggleDownloadExt").waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smugglePreset").waitFor({ state: "visible", timeout: 10000 });
    await waitForPageCondition(
      `smuggle optional settings start collapsed (${name})`,
      () => (
        document.getElementById("smugglePageSettings")?.open === false &&
        document.getElementById("smuggleAdvancedSettings")?.open === false &&
        !document.getElementById("smugglePreview")
      ),
      null,
      10000
    );
    await page.locator("#smuggleSubmitBtn").waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smuggleCancelBtn").waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smuggleEncryption").waitFor({ state: "attached", timeout: 10000 });
    await chooseSmuggleCombobox("smuggleEncryption", "none");

    await page.locator("#smuggleDownloadName").fill("Quarterly-Report");
    await chooseSmuggleCombobox("smuggleDownloadExt", "pdf");
    await chooseSmuggleCombobox("smugglePreset", "card_auto");
    await page.locator("#smugglePageSettings > summary").click();
    await page.locator("#smuggleTitleInput").fill("Quarterly Report");
    await page.locator("#smuggleMessageInput").fill("Internal SMUGGLING test");
    await page.locator("#smuggleDelayMs").fill("1200");

    await page.evaluate(() => {
      const http = window.XferryApp.service("http");
      const modalNode = document.getElementById("smuggleModal");
      const state = {
        calls: [],
        originalAdapter: null,
        release: null,
      };
      let originalAdapter = null;
      const pendingAdapter = (method, url, ...args) => {
        if (String(method).toUpperCase() !== "SMUGGLE") {
          return originalAdapter(method, url, ...args);
        }
        state.calls.push({ method: String(method), url: String(url) });
        return new Promise(resolve => {
          state.release = resolve;
        });
      };
      originalAdapter = http["set-adapter"](pendingAdapter);
      state.originalAdapter = originalAdapter;
      window.__smugglePendingContract = state;
      window.__smuggleModalIdentity = modalNode;
    });

    await page.locator("#smuggleSubmitBtn").click();
    await page.locator("#smuggleSubmitBtn").dispatchEvent("click");
    await page.keyboard.press("Escape");
    await page.evaluate(() => {
      const overlay = document.querySelector("#smuggleModal .modal-overlay");
      overlay?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
    await waitForPageCondition(
      `smuggle pending blocks duplicate submit and dismissal (${name})`,
      () => {
        const contract = window.__smugglePendingContract;
        const modalNode = document.getElementById("smuggleModal");
        const dialog = modalNode?.querySelector(".smuggle-dialog");
        const submit = document.getElementById("smuggleSubmitBtn");
        const cancel = document.getElementById("smuggleCancelBtn");
        const close = modalNode?.querySelector(".smuggle-dialog__close");
        return Boolean(
          modalNode &&
          modalNode === window.__smuggleModalIdentity &&
          modalNode.dataset.smugglePhase === "submitting" &&
          dialog?.getAttribute("aria-busy") === "true" &&
          submit?.disabled && cancel?.disabled && close?.disabled &&
          document.getElementById("smuggleDownloadName")?.disabled &&
          document.activeElement?.id === "smuggleInlineStatus" &&
          contract?.calls.length === 1 &&
          typeof contract.release === "function" &&
          !document.getElementById("smuggleResultModal")
        );
      },
      null,
      10000
    );

    await page.evaluate(() => {
      const contract = window.__smugglePendingContract;
      contract.release(new Response(JSON.stringify({
        error: {
          code: "invalid_smuggle_configuration",
          message: "Browser smoke rejected the requested extracted name.",
          field: "download_name",
          details: {},
        },
      }), {
        status: 400,
        statusText: "Bad Request",
        headers: { "Content-Type": "application/json" },
      }));
    });
    await waitForPageCondition(
      `smuggle inline error keeps values and modal identity (${name})`,
      () => {
        const modalNode = document.getElementById("smuggleModal");
        const status = document.getElementById("smuggleInlineStatus")?.textContent || "";
        const isEnglish = document.documentElement.lang.toLowerCase().startsWith("en");
        const localized = isEnglish
          ? "SMUGGLE settings were rejected."
          : "Настройки SMUGGLE отклонены.";
        const retry = isEnglish
          ? "Edit the settings and generate again."
          : "Исправьте настройки и повторите генерацию.";
        return Boolean(
          modalNode &&
          modalNode === window.__smuggleModalIdentity &&
          modalNode.dataset.smugglePhase === "editing" &&
          modalNode.querySelector(".smuggle-dialog")?.getAttribute("aria-busy") === "false" &&
          document.getElementById("smuggleDownloadName")?.value === "Quarterly-Report" &&
          document.getElementById("smuggleDownloadExt")?.value === "pdf" &&
          document.getElementById("smugglePreset")?.value === "card_auto" &&
          document.getElementById("smuggleTitleInput")?.value === "Quarterly Report" &&
          document.getElementById("smuggleMessageInput")?.value === "Internal SMUGGLING test" &&
          document.getElementById("smuggleDelayMs")?.value === "1200" &&
          status.includes(localized) &&
          status.includes("invalid_smuggle_configuration") &&
          status.includes("download_name") &&
          status.includes(retry) &&
          document.activeElement?.id === "smuggleDownloadName" &&
          !document.getElementById("smuggleSubmitBtn")?.disabled &&
          !document.getElementById("smuggleCancelBtn")?.disabled
        );
      },
      null,
      10000
    );
    await page.evaluate(() => {
      const contract = window.__smugglePendingContract;
      if (contract) {
        window.XferryApp.service("http")["set-adapter"](contract.originalAdapter);
      }
      delete window.__smugglePendingContract;
    });

    await page.locator("#smuggleSubmitBtn").click();
    await waitForPageCondition(
      `smuggle builder promotes to success (${name})`,
      () => {
        const modalNode = document.getElementById("smuggleModal");
        const editingPanel = modalNode?.querySelector('[data-smuggle-panel="editing"]');
        const successPanel = modalNode?.querySelector('[data-smuggle-panel="success"]');
        return Boolean(
          modalNode &&
          modalNode === window.__smuggleModalIdentity &&
          modalNode.dataset.smugglePhase === "success" &&
          editingPanel?.hidden &&
          successPanel && !successPanel.hidden &&
          document.getElementById("smuggleDialogBody")?.scrollTop <= 1 &&
          !document.getElementById("smuggleResultModal")
        );
      },
      null,
      10000
    );

    const unexpectedPopup = await page.waitForEvent("popup", { timeout: 1000 }).catch(() => null);
    if (unexpectedPopup) {
      await unexpectedPopup.close().catch(() => {});
      throw new Error("SMUGGLE artifact opened before explicit result action");
    }

    await page.locator('#smuggleModal [role="dialog"]').waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smuggleCopyUrlBtn").waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smuggleOpenBtn").waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smuggleSaveBtn").waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smuggleEditBtn").waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smuggleCloseBtn").waitFor({ state: "visible", timeout: 10000 });

    const generatedSummary = await page.evaluate(() => (
      document.documentElement.lang.toLowerCase().startsWith("en")
        ? "HTML generated"
        : "HTML сгенерирован"
    ));
    await waitForFilesSummaryText(["SMUGGLE", `/uploads/${name}`, generatedSummary], 10000);
    await waitForText(page.locator("#smuggleSuccessPanel"), "Quarterly-Report.pdf", 10000);
    await waitForText(page.locator("#smuggleSuccessPanel"), /\/uploads\/smuggle_[^/\s]+\.html/, 10000);
    const normalizedBaseUrl = String(baseUrl || "").replace(/\/$/, "");
    await waitForPageCondition(
      `smuggle result dialog a11y summary (${name})`,
      ([expectedName, expectedUrlPrefix]) => {
        const dialog = document.querySelector('#smuggleModal [role="dialog"]');
        if (!dialog) {
          return false;
        }
        const text = dialog.textContent || "";
        return text.includes(expectedName) && text.includes(expectedUrlPrefix);
      },
      [name, `${normalizedBaseUrl}/uploads/smuggle_`],
      10000
    );

    await waitForPageCondition(
      `smuggle result dialog initial focus (${name})`,
      () => document.activeElement?.id === "smuggleCopyUrlBtn",
      null,
      10000
    );
    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle result dialog tab to open (${name})`,
      () => document.activeElement?.id === "smuggleOpenBtn",
      null,
      10000
    );
    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle result dialog tab to save (${name})`,
      () => document.activeElement?.id === "smuggleSaveBtn",
      null,
      10000
    );
    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle result dialog tab to edit (${name})`,
      () => document.activeElement?.id === "smuggleEditBtn",
      null,
      10000
    );
    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle result dialog tab to close (${name})`,
      () => document.activeElement?.id === "smuggleCloseBtn",
      null,
      10000
    );
    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle result dialog wraps to header close (${name})`,
      () => document.activeElement?.classList?.contains("smuggle-dialog__close"),
      null,
      10000
    );
    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle result dialog reaches technical disclosure (${name})`,
      () => document.activeElement?.parentElement?.id === "smuggleResultDetails",
      null,
      10000
    );
    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle result dialog wraps to copy after disclosure (${name})`,
      () => document.activeElement?.id === "smuggleCopyUrlBtn",
      null,
      10000
    );

    await page.locator("#smuggleCopyUrlBtn").click();
    await assertClipboardSnapshot("smuggle-url", [`${normalizedBaseUrl}/uploads/smuggle_`], 10000);

    const popupUrl = await openSmuggleArtifactPopupAndAssert(
      () => page.locator("#smuggleOpenBtn").click(),
      "Quarterly-Report.pdf"
    );
    await page.locator("#smuggleCloseBtn").click();
    await modal.waitFor({ state: "detached", timeout: 10000 });
    await page.evaluate(() => {
      delete window.__smuggleModalIdentity;
    });

    await waitForPageCondition(
      `smuggle result dialog focus restored (${name})`,
      ([targetPath]) => {
        const active = document.activeElement;
        return Boolean(
          active?.matches(".file-row__more > summary") &&
          active.closest(".file-row__more")?.querySelector(
            `[data-file-action="smuggle"][data-path="${targetPath}"]`
          )
        );
      },
      [encodeURIComponent(`/uploads/${name}`)],
      10000
    );
    return popupUrl;
  }

  async function smuggleViaRequestPanelAndAssert(name) {
    const uploadPath = `/uploads/${name}`;

    await page.locator("#pathInput").fill(uploadPath);
    await triggerRequestMethod("SMUGGLE");

    const modal = page.locator("#smuggleModal");
    await modal.waitFor({ state: "attached", timeout: 10000 });
    await page.evaluate(() => {
      window.__smuggleRequestModalIdentity = document.getElementById("smuggleModal");
    });
    await page.locator("#smuggleDownloadName").waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smuggleDownloadExt").waitFor({ state: "visible", timeout: 10000 });
    await page.locator("#smugglePreset").waitFor({ state: "visible", timeout: 10000 });

    await page.locator("#smuggleDownloadName").fill("Request-Panel-Smuggling");
    await chooseSmuggleCombobox("smuggleDownloadExt", "txt");
    await chooseSmuggleCombobox("smugglePreset", "card_manual");
    await page.locator("#smugglePageSettings > summary").click();
    await page.locator("#smuggleTitleInput").fill("Request Panel SMUGGLING");
    await page.locator("#smuggleMessageInput").fill("Request panel SMUGGLING test");
    await page.locator("#smuggleCtaLabelInput").fill("Download from request panel");
    await page.locator("#smuggleSubmitBtn").click();
    await waitForPageCondition(
      `request panel smuggle promotes to success (${name})`,
      () => {
        const modalNode = document.getElementById("smuggleModal");
        return Boolean(
          modalNode &&
          modalNode === window.__smuggleRequestModalIdentity &&
          modalNode.dataset.smugglePhase === "success" &&
          !document.getElementById("smuggleResultModal")
        );
      },
      null,
      10000
    );

    await waitForText(page.locator("#requestPreviewArea"), `SMUGGLE ${uploadPath}?`, 10000);
    await waitForText(page.locator("#responseArea"), "HTTP/1.1 200 OK", 10000);
    await waitForText(page.locator("#responseArea"), "Request-Panel-Smuggling.txt", 10000);
    await waitForLiveRegionText("responseAreaLive", /HTML сгенерирован|HTML generated/, 10000);
    await waitForText(page.locator("#smuggleSuccessPanel"), "Request-Panel-Smuggling.txt", 10000);

    const popupUrl = await openSmuggleArtifactPopupAndAssert(
      () => page.locator("#smuggleOpenBtn").click(),
      "Request-Panel-Smuggling.txt",
      { manualStart: true }
    );
    await page.locator("#smuggleCloseBtn").click();
    await modal.waitFor({ state: "detached", timeout: 10000 });
    await page.evaluate(() => {
      delete window.__smuggleRequestModalIdentity;
    });

    await waitForPageCondition(
      `request panel smuggle focus restored (${name})`,
      () => {
        const active = document.activeElement;
        return active?.getAttribute("data-request-method") === "SMUGGLE" || active?.id === "pathInput";
      },
      null,
      10000
    );

    return popupUrl;
  }

  async function assertNoLingeringSmugglePopupPages(label) {
    await page.waitForTimeout(50);
    const lingeringPages = page.context().pages().filter(
      (candidate) => candidate !== page && !candidate.isClosed()
    );
    if (lingeringPages.length === 0) {
      return;
    }

    const snapshot = lingeringPages.map((candidate) => ({
      url: candidate.url(),
    }));
    await Promise.all(
      lingeringPages.map((candidate) => candidate.close().catch(() => {}))
    );
    throw new Error(`${label}: lingering SMUGGLE popup pages: ${JSON.stringify(snapshot)}`);
  }

  async function openSmuggleArtifactPopupAndAssert(openPopup, expectedName, options = {}) {
    const popupPromise = page.waitForEvent("popup", { timeout: 5000 });
    await openPopup();
    const popup = await popupPromise;
    const popupUrl = popup ? popup.url() : "";
    try {
      await assertSmuggleArtifactPopupCompletes(popup, expectedName, options);
      return popupUrl;
    } finally {
      await assertNoLingeringSmugglePopupPages(`SMUGGLE popup cleanup (${expectedName})`);
    }
  }

  async function assertSmuggleArtifactPopupCompletes(popup, expectedName, options = {}) {
    const { password = null, manualStart = false, expectedContent = null } = options;
    if (!popup) {
      throw new Error("SMUGGLE artifact popup did not open");
    }

    const downloadPromise = popup.waitForEvent("download", { timeout: 10000 }).then(
      (download) => ({ download, error: null }),
      (error) => ({ download: null, error })
    );
    try {
      await popup.waitForLoadState("domcontentloaded");

      const acceptedSafeBuilderStatuses = [
        `Downloaded: ${expectedName}`,
        `Скачано: ${expectedName}`,
        "Download started",
      ];
      if (password) {
        await popup.locator("#smugglePassword").fill(password);
        const passwordButton = await popup.locator("#downloadBtn").count()
          ? popup.locator("#downloadBtn")
          : popup.locator("#smugglePasswordGate button");
        await passwordButton.click();
        await waitForPopupCondition(
          `encrypted SMUGGLE artifact popup status reaches completion (${expectedName})`,
          popup,
          ([acceptedSafeBuilderStatuses]) => {
            const message = document.getElementById("smuggleStatus") ||
              document.getElementById("smugglePasswordStatus");
            return Boolean(message && acceptedSafeBuilderStatuses.includes(message.textContent));
          },
          [acceptedSafeBuilderStatuses],
          10000
        );
      } else {
        if (manualStart) {
          await popup.locator("#downloadBtn").click();
        }
        await waitForPopupCondition(
          `SMUGGLE artifact popup status reaches completion (${expectedName})`,
          popup,
          ([targetName, acceptedSafeBuilderStatuses]) => {
            const safeStatus = document.getElementById("smuggleStatus");
            if (safeStatus && acceptedSafeBuilderStatuses.includes(safeStatus.textContent)) {
              return true;
            }
            return false;
          },
          [expectedName, acceptedSafeBuilderStatuses],
          10000
        );
      }

      const downloadOutcome = await downloadPromise;
      if (!downloadOutcome.download) {
        const snapshot = popup.isClosed() ? { closed: true } : await popup.evaluate(() => ({
          url: window.location.href,
          status: document.getElementById("smuggleStatus")?.textContent ||
            document.getElementById("smugglePasswordStatus")?.textContent || "",
          hasDownloadButton: Boolean(document.getElementById("downloadBtn")),
          hasPasswordInput: Boolean(document.getElementById("p")),
          bodyText: (document.body?.innerText || "").slice(0, 500),
        }));
        throw new Error(
          `SMUGGLE artifact emitted no download: ${JSON.stringify(snapshot)}; ` +
          String(downloadOutcome.error?.message || downloadOutcome.error || "timeout")
        );
      }
      const download = downloadOutcome.download;
      const suggestedFilename = download.suggestedFilename();
      if (suggestedFilename !== expectedName) {
        throw new Error(`SMUGGLE artifact download filename mismatch: ${suggestedFilename}`);
      }
      if (expectedContent !== null) {
        const stream = await download.createReadStream();
        if (!stream) {
          throw new Error(`SMUGGLE artifact download stream is unavailable: ${expectedName}`);
        }
        const bytes = [];
        for await (const chunk of stream) {
          bytes.push(...chunk);
        }
        let downloadedContent = "";
        for (let offset = 0; offset < bytes.length; offset += 8192) {
          downloadedContent += String.fromCharCode(...bytes.slice(offset, offset + 8192));
        }
        if (downloadedContent !== expectedContent) {
          throw new Error(
            `SMUGGLE artifact download content mismatch: ${JSON.stringify({
              expectedName,
              expectedContent,
              downloadedContent,
            })}`
          );
        }
      }
    } finally {
      await popup.close().catch(() => {});
    }
  }

  function assertCapturedSmuggleRequestUrl(url, expectedMode, expectedEncryption) {
    const rawUrl = String(url);
    const queryStart = rawUrl.indexOf("?");
    const fragmentStart = rawUrl.indexOf("#", queryStart + 1);
    const query = queryStart < 0
      ? ""
      : rawUrl.slice(queryStart + 1, fragmentStart < 0 ? undefined : fragmentStart);
    const entries = new Map();
    for (const pair of query.split("&")) {
      if (!pair) continue;
      const separator = pair.indexOf("=");
      const rawName = separator < 0 ? pair : pair.slice(0, separator);
      const rawValue = separator < 0 ? "" : pair.slice(separator + 1);
      const decode = (value) => decodeURIComponent(String(value).replace(/\+/g, " "));
      entries.set(decode(rawName), decode(rawValue));
    }
    const params = {
      get: (name) => entries.has(name) ? entries.get(name) : null,
      has: (name) => entries.has(name),
    };
    const hasLegacyParameter = ["encrypt", "use_constructor", "b64"].some((name) => params.has(name));
    const valid = (
      params.get("mode") === expectedMode &&
      params.get("encryption") === expectedEncryption &&
      !hasLegacyParameter
    );
    if (!valid) {
      throw new Error(
        `SMUGGLE request query contract failed: ${JSON.stringify({
          url: rawUrl,
          expectedMode,
          expectedEncryption,
          mode: params.get("mode"),
          encryption: params.get("encryption"),
          hasEncrypt: params.has("encrypt"),
          hasUseConstructor: params.has("use_constructor"),
          hasB64: params.has("b64"),
        })}`
      );
    }
    return String(url);
  }

  async function smuggleViaModalAndAssert(name, encryption, options = {}) {
    const { mode: expectedMode = "simple", expectedContent = null } = options;
    if (!["none", "xor", "aes"].includes(encryption)) {
      throw new Error(`Unsupported SMUGGLE encryption for browser smoke: ${encryption}`);
    }
    if (!["simple", "constructor"].includes(expectedMode)) {
      throw new Error(`Unsupported SMUGGLE mode for browser smoke: ${expectedMode}`);
    }
    const actionButton = await getServerFileAction(name, "smuggle");
    await actionButton.click();
    const modal = page.locator("#smuggleModal");
    await modal.waitFor({ state: "attached", timeout: 10000 });
    if (expectedMode === "constructor") {
      await page.locator("#smuggleAdvancedSettings > summary").click();
      await page.locator("#smuggleConstructorEnabled").check();
    }
    if (expectedMode === "simple" && encryption === "none") {
      await chooseSmuggleCombobox("smugglePreset", "card_manual");
    }
    await chooseSmuggleCombobox("smuggleEncryption", encryption);
    const requestPromise = page.waitForRequest(
      (request) => String(request.method()).toUpperCase() === "SMUGGLE",
      { timeout: 10000 }
    );
    await page.locator("#smuggleSubmitBtn").click();
    const capturedRequest = await requestPromise;
    const requestUrl = assertCapturedSmuggleRequestUrl(
      capturedRequest.url(),
      expectedMode,
      encryption
    );
    await waitForPageCondition(
      `smuggle ${expectedMode}/${encryption} modal promotes to success (${name})`,
      ([encryption, expectedMode]) => {
        const modalNode = document.getElementById("smuggleModal");
        const builder = modalNode?.__smuggleResult?.builder;
        const hasPassword = Boolean(
          builder && Object.prototype.hasOwnProperty.call(builder, "password")
        );
        const password = builder?.password;
        return Boolean(
          modalNode?.dataset.smugglePhase === "success" &&
          builder?.schema_version === 1 &&
          builder?.mode === expectedMode &&
          builder?.encryption === encryption &&
          (encryption === "none"
            ? !hasPassword
            : typeof password === "string" && password.length > 0) &&
          (encryption === "none"
            ? !document.querySelector('[data-dialog-action="copy-password"]')?.checkVisibility()
            : document.getElementById("smuggleResultPassword")?.textContent?.trim() === password &&
              document.querySelector('[data-dialog-action="copy-password"]')?.checkVisibility()) &&
          document.getElementById("smuggleResultDetails")?.open === false
        );
      },
      [encryption, expectedMode],
      10000
    );
    const result = await page.evaluate(() => {
      const modalNode = document.getElementById("smuggleModal");
      const builder = modalNode?.__smuggleResult?.builder || {};
      return {
        schemaVersion: builder?.schema_version,
        mode: builder?.mode || "",
        encryption: builder?.encryption || "",
        hasPassword: Object.prototype.hasOwnProperty.call(builder, "password"),
        password: builder?.password || "",
        url: document.getElementById("smuggleResultUrl")?.textContent?.trim() || "",
      };
    });
    const passwordExpected = encryption !== "none";
    if (
      result.schemaVersion !== 1 ||
      result.mode !== expectedMode ||
      result.encryption !== encryption ||
      result.hasPassword !== passwordExpected ||
      (passwordExpected && !result.password) ||
      !result.url
    ) {
      throw new Error(`SMUGGLE modal missing canonical verification data: ${JSON.stringify(result)}`);
    }

    if (passwordExpected) {
      await page.locator('[data-dialog-action="copy-password"]').click();
      await assertClipboardSnapshot("smuggle-password", [result.password], 10000);
    }
    try {
      await openSmuggleArtifactPopupAndAssert(
        () => page.locator("#smuggleOpenBtn").click(),
        name,
        {
          password: passwordExpected ? result.password : null,
          manualStart: !passwordExpected,
          expectedContent,
        }
      );
    } catch (error) {
      throw new Error(
        `SMUGGLE ${expectedMode}/${encryption} artifact verification failed: ${error.message}`
      );
    }
    await page.locator("#smuggleCloseBtn").click();
    await modal.waitFor({ state: "detached", timeout: 10000 });

    return {
      url: result.url.replace(/^https?:\/\/[^/]+/, ""),
      requestUrl,
      schemaVersion: result.schemaVersion,
      mode: result.mode,
      encryption: result.encryption,
    };
  }

  async function assertSmuggleDialogKeyboardContract(name) {
    const encodedPath = encodeURIComponent(`/uploads/${name}`);
    const actionButton = await getServerFileAction(name, "smuggle");
    await actionButton.waitFor({ state: "visible", timeout: 10000 });
    await actionButton.focus();
    await waitForPageCondition(
      `smuggle action focused (${name})`,
      ([targetPath]) => {
        const active = document.activeElement;
        return Boolean(
          active &&
          active.getAttribute("data-file-action") === "smuggle" &&
          active.getAttribute("data-path") === targetPath
        );
      },
      [encodedPath],
      10000
    );

    await actionButton.press("Enter");
    const modal = page.locator("#smuggleModal");
    await modal.waitFor({ state: "attached", timeout: 10000 });
    await page.locator('#smuggleModal [role="dialog"]').waitFor({ state: "visible", timeout: 10000 });

    await waitForPageCondition(
      `smuggle dialog initial focus (${name})`,
      () => document.activeElement?.id === "smuggleDownloadName",
      null,
      10000
    );

    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle dialog tab to extension (${name})`,
      () => document.activeElement?.id === "smuggleDownloadExt",
      null,
      10000
    );

    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle dialog tab to encryption (${name})`,
      () => document.activeElement?.id === "smuggleEncryption",
      null,
      10000
    );

    await page.keyboard.press("Shift+Tab");
    await waitForPageCondition(
      `smuggle dialog reverse to extension (${name})`,
      () => document.activeElement?.id === "smuggleDownloadExt",
      null,
      10000
    );

    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle dialog tab to preset (${name})`,
      () => document.activeElement?.id === "smugglePreset",
      null,
      10000
    );

    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle dialog tab to page settings (${name})`,
      () => document.activeElement?.parentElement?.id === "smugglePageSettings",
      null,
      10000
    );

    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle dialog tab to advanced settings (${name})`,
      () => document.activeElement?.parentElement?.id === "smuggleAdvancedSettings",
      null,
      10000
    );
    await page.keyboard.press("Enter");
    await waitForPageCondition(
      `smuggle advanced settings open from keyboard (${name})`,
      () => document.getElementById("smuggleAdvancedSettings")?.open === true,
      null,
      10000
    );
    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `smuggle dialog tab to constructor toggle (${name})`,
      () => document.activeElement?.id === "smuggleConstructorEnabled",
      null,
      10000
    );

    await page.keyboard.press("Escape");
    await page.locator("#smuggleModal").waitFor({ state: "detached", timeout: 10000 });

    await waitForPageCondition(
      `smuggle dialog focus restored (${name})`,
      ([targetPath]) => {
        const active = document.activeElement;
        return Boolean(
          active?.matches(".file-row__more > summary") &&
          active.closest(".file-row__more")?.querySelector(
            `[data-file-action="smuggle"][data-path="${targetPath}"]`
          )
        );
      },
      [encodedPath],
      10000
    );
  }

  async function infoViaServerFilesAndAssert(name, options = {}) {
    const requestPath = `/uploads/${name}`;
    const encodedPath = encodeURIComponent(requestPath);
    const detailsTrigger = await getServerFileDetailsTrigger(name);
    const beforePath = await page.locator("#browsePathInput").inputValue();
    const lang = await page.locator("html").getAttribute("lang");
    const expectedLabels = lang === "en"
      ? ["File name", "Size", "Content-Type", "MIME source", "Content assessment", "Extension", "Created", "Modified"]
      : ["Имя файла", "Размер", "Content-Type", "Источник MIME", "Оценка содержимого", "Расширение", "Создан", "Изменён"];
    const expectedTitle = lang === "en" ? "File details received" : "Сведения о файле получены";
    const expectedExpand = lang === "en" ? "Show file details" : "Показать сведения о файле";
    const expectedCollapse = lang === "en" ? "Hide file details" : "Скрыть сведения о файле";
    const summaryBefore = await page.locator('[data-tool-summary-scope="files"]').evaluate((summary) => ({
      phase: summary.dataset.phase || "",
      text: (summary.innerText || summary.textContent || "").trim(),
    }));
    const matchesInlineInfoRequest = request => {
      const requestUrl = request.url();
      const queryIndex = requestUrl.indexOf("?");
      const encodedPath = queryIndex === -1 ? requestUrl : requestUrl.slice(0, queryIndex);
      return request.method() === "INFO" && decodeURIComponent(encodedPath).endsWith(requestPath);
    };
    const expectRequest = options.expectRequest !== false;
    const infoRequest = expectRequest
      ? page.waitForRequest(matchesInlineInfoRequest)
      : page.waitForRequest(matchesInlineInfoRequest, { timeout: 750 }).catch(() => null);

    if (options.activation === "enter") {
      await detailsTrigger.focus();
      await page.keyboard.press("Enter");
    } else if (options.activation === "space") {
      await detailsTrigger.focus();
      await page.keyboard.press("Space");
    } else {
      await detailsTrigger.click();
    }

    const observedInfoRequest = await infoRequest;
    if (expectRequest) {
      const inspectionRequestUrl = observedInfoRequest.url();
      if (!inspectionRequestUrl.endsWith("?inspect=true")) {
        throw new Error(`Inline file details INFO did not opt into inspection: ${inspectionRequestUrl}`);
      }
    } else if (observedInfoRequest) {
      throw new Error(`Cached inline file details unexpectedly sent INFO: ${observedInfoRequest.url()}`);
    }

    await waitForPageCondition(
      `file INFO renders inline details without navigating (${requestPath})`,
      ([targetPath, targetEncodedPath, originalPath, filename, labels, beforeSummary]) => {
        const pathInput = document.getElementById("browsePathInput");
        const summaryRoot = document.querySelector('[data-tool-summary-scope="files"]');
        const summaryText = (summaryRoot?.innerText || summaryRoot?.textContent || "").trim();
        const trigger = document.querySelector(
          `#serverFiles [data-file-details-trigger][data-path="${targetEncodedPath}"]`
        );
        const panel = trigger?.getAttribute("aria-controls")
          ? document.getElementById(trigger.getAttribute("aria-controls"))
          : null;
        const panelText = (panel?.innerText || panel?.textContent || "").trim();
        return Boolean(
          pathInput?.value === originalPath &&
          trigger?.getAttribute("aria-expanded") === "true" &&
          trigger.getAttribute("aria-label")?.includes(filename) &&
          panel &&
          !panel.hidden &&
          panel.getAttribute("role") === "region" &&
          panel.getAttribute("aria-busy") === "false" &&
          panelText.includes(filename) &&
          labels.every(label => panelText.includes(label)) &&
          summaryRoot?.dataset.phase === beforeSummary.phase &&
          summaryText === beforeSummary.text &&
          !document.querySelector("#appDialog [role='dialog'], #appDialog [role='alertdialog']") &&
          !document.querySelector("#filesHttpErrorHost .http-error-card") &&
          !Array.from(document.querySelectorAll(`#serverFiles [data-file-action][data-path="${targetEncodedPath}"]`))
            .some(action => action.dataset.fileAction === "info")
        );
      },
      [requestPath, encodedPath, beforePath, name, expectedLabels, summaryBefore],
      10000
    );
    if (expectRequest) {
      await waitForLiveRegionText("filesResponseAreaLive", `${expectedTitle}: ${name}`, 10000);
    }
    if (await page.locator("#browsePathInput").inputValue() !== beforePath) {
      throw new Error(`Files Details changed browse path: ${beforePath}`);
    }

    const detailsGeometry = await page.locator(
      `#serverFiles [data-file-details-trigger][data-path="${encodedPath}"]`
    ).evaluate((trigger, labels) => {
      const panel = document.getElementById(trigger.getAttribute("aria-controls"));
      const row = trigger.closest(".uploaded-file");
      const fields = Array.from(panel?.querySelectorAll(".file-row__details-field") || []);
      const labelOffsets = fields.map(field => ({
        label: field.querySelector("dt")?.textContent?.trim() || "",
        top: field.querySelector("dt")?.getBoundingClientRect().top || 0,
      }));
      return {
        triggerExpanded: trigger.getAttribute("aria-expanded"),
        triggerLabel: trigger.getAttribute("aria-label") || "",
        triggerControls: trigger.getAttribute("aria-controls") || "",
        panelId: panel?.id || "",
        panelRole: panel?.getAttribute("role") || "",
        panelLabelledBy: panel?.getAttribute("aria-labelledby") || "",
        panelHidden: Boolean(panel?.hidden),
        fieldCount: fields.length,
        labels: labelOffsets.map(entry => entry.label),
        labelOffsets,
        hasHorizontalOverflow: Boolean(
          panel && (
            panel.scrollWidth > panel.clientWidth + 1 ||
            row?.scrollWidth > row.clientWidth + 1 ||
            document.documentElement.scrollWidth > innerWidth + 1
          )
        ),
      };
    }, expectedLabels);
    const metadataTopsIncrease = detailsGeometry.labelOffsets.every((entry, index, entries) => (
      index === 0 || entry.top >= entries[index - 1].top
    ));
    if (
      detailsGeometry.triggerExpanded !== "true" ||
      !detailsGeometry.triggerLabel.includes(expectedCollapse) ||
      detailsGeometry.triggerControls !== detailsGeometry.panelId ||
      detailsGeometry.panelRole !== "region" ||
      detailsGeometry.panelLabelledBy.length === 0 ||
      detailsGeometry.panelHidden ||
      detailsGeometry.fieldCount !== 8 ||
      expectedLabels.some(label => !detailsGeometry.labels.includes(label)) ||
      detailsGeometry.hasHorizontalOverflow ||
      !metadataTopsIncrease
    ) {
      throw new Error(`Files Details inline metadata geometry failed: ${JSON.stringify(detailsGeometry)}`);
    }

    if (options.capture) {
      await page.screenshot({
        path: `${artifactDir}/files-details-inline-${lang === "en" ? "en" : "ru"}.png`,
        fullPage: true,
      });
    }

    if (options.verifyCache) {
      await detailsTrigger.click();
      await waitForPageCondition(
        `Files Details collapsed before cache check (${name})`,
        ([targetPath]) => (
          document.querySelector(`#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`)
            ?.getAttribute("aria-expanded") === "false"
        ),
        [encodedPath]
      );
      const unexpectedInfo = page.waitForRequest(request => {
        const requestUrl = request.url();
        const queryIndex = requestUrl.indexOf("?");
        const encodedRequestPath = queryIndex === -1 ? requestUrl : requestUrl.slice(0, queryIndex);
        return request.method() === "INFO" && decodeURIComponent(encodedRequestPath).endsWith(requestPath);
      }, { timeout: 750 }).catch(() => null);
      await detailsTrigger.click();
      await waitForPageCondition(
        `Files Details cached reopen renders without request (${name})`,
        ([targetPath, filename]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          return Boolean(
            trigger?.getAttribute("aria-expanded") === "true" &&
            panel &&
            !panel.hidden &&
            (panel.innerText || panel.textContent || "").includes(filename)
          );
        },
        [encodedPath, name]
      );
      const cachedRequest = await unexpectedInfo;
      if (cachedRequest) {
        throw new Error(`Cached inline file details sent a new INFO request: ${cachedRequest.url()}`);
      }
    }

    if (options.close === "escape") {
      await detailsTrigger.focus();
      await page.keyboard.press("Escape");
      await waitForPageCondition(
        `Files Details Escape collapses and restores trigger focus (${name})`,
        ([targetPath, expandLabel]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          return Boolean(
            trigger &&
            document.activeElement === trigger &&
            trigger.getAttribute("aria-expanded") === "false" &&
            trigger.getAttribute("aria-label")?.includes(expandLabel) &&
            panel?.hidden
          );
        },
        [encodedPath, expectedExpand]
      );
    } else {
      await detailsTrigger.click();
      await waitForPageCondition(
        `Files Details trigger click collapses (${name})`,
        ([targetPath, expandLabel]) => {
          const trigger = document.querySelector(
            `#serverFiles [data-file-details-trigger][data-path="${targetPath}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          return Boolean(
            trigger?.getAttribute("aria-expanded") === "false" &&
            trigger.getAttribute("aria-label")?.includes(expandLabel) &&
            panel?.hidden
          );
        },
        [encodedPath, expectedExpand]
      );
    }

    return requestPath;
  }

  async function deleteViaServerFilesAndAssert(name) {
    const encodedPath = encodeURIComponent(`/uploads/${name}`);
    const actionButton = await getServerFileAction(name, "delete");
    await actionButton.waitFor({ state: "visible", timeout: 10000 });

    await actionButton.click();
    await confirmAppDialog(name, 10000);

    await waitForPageCondition(
      `deleted file action removed from serverFiles (${name})`,
      ([targetPath]) => {
        return !document.querySelector(`#serverFiles [data-path="${targetPath}"]`);
      },
      [encodedPath],
      10000
    );
    await waitForPageCondition(
      `focus anchored after delete (${name})`,
      () => document.activeElement?.id === "browsePathInput",
      null,
      10000
    );
    const deletedSummary = await page.evaluate(() => (
      document.documentElement.lang.toLowerCase().startsWith("en")
        ? "File deleted"
        : "Файл удалён"
    ));
    await assertFilesRefreshPreservesCompletedSummary(
      [deletedSummary, `/uploads/${name}`],
      `single delete ${name}`
    );
  }

  async function assertDeleteDialogKeyboardContract(name) {
    const actionButton = await getServerFileAction(name, "delete");
    await actionButton.waitFor({ state: "visible", timeout: 10000 });
    await actionButton.focus();
    const encodedPath = encodeURIComponent(`/uploads/${name}`);
    await waitForPageCondition(
      `delete action focused (${name})`,
      ([targetPath]) => {
        const active = document.activeElement;
        return Boolean(
          active &&
          active.getAttribute("data-file-action") === "delete" &&
          active.getAttribute("data-path") === targetPath
        );
      },
      [encodedPath],
      10000
    );

    await actionButton.press("Enter");
    const dialog = page.locator('#appDialog [role="alertdialog"]');
    await dialog.waitFor({ state: "visible", timeout: 10000 });

    await waitForPageCondition(
      `delete dialog initial focus (${name})`,
      () => document.activeElement?.getAttribute("data-dialog-action") === "cancel",
      null,
      10000
    );

    await page.keyboard.press("Shift+Tab");
    await waitForPageCondition(
      `delete dialog reverse tab trap (${name})`,
      () => document.activeElement?.getAttribute("data-dialog-action") === "confirm",
      null,
      10000
    );

    await page.keyboard.press("Tab");
    await waitForPageCondition(
      `delete dialog forward tab trap (${name})`,
      () => document.activeElement?.getAttribute("data-dialog-action") === "cancel",
      null,
      10000
    );

    await page.keyboard.press("Escape");
    await page.locator("#appDialog").waitFor({ state: "detached", timeout: 10000 });

    await waitForPageCondition(
      `delete dialog focus restored (${name})`,
      ([targetPath]) => {
        const active = document.activeElement;
        return Boolean(
          active?.matches(".file-row__more > summary") &&
          active.closest(".file-row__more")?.querySelector(
            `[data-file-action="delete"][data-path="${targetPath}"]`
          )
        );
      },
      [encodedPath],
      10000
    );
  }

  async function assertAdvancedSessionControlContract() {
    await page.locator("#tab-opsec").click();
    await waitForTabState("opsec", { focused: true });
    await switchLanguage("en");
    await waitForAdvancedSessionReady();

    const surface = await page.evaluate(() => {
      const app = window.XferryApp;
      const session = app.service("advanced-session");
      const snapshot = session.getSnapshot();
      const transient = session.attachSessionHeader({ headers: { Existing: "yes" } });
      const token = transient.headers["X-XFerry-Advanced-Session"];
      const renderedText = document.documentElement.innerText;
      const inspectorText = document.getElementById("opsecRequestArea")?.innerText || "";
      const storageText = [
        ...Object.values(localStorage),
        ...Object.values(sessionStorage),
      ].join("\n");
      return {
        methods: app.describe().services["advanced-session"],
        active: snapshot.active,
        phase: snapshot.phase,
        prefix: snapshot.prefix,
        decoder: snapshot.decoder,
        panelPhase: document.getElementById("advancedSessionPanel")?.dataset.sessionPhase,
        status: document.getElementById("advancedSessionStatus")?.textContent || "",
        tokenShape: /^[A-Za-z0-9_-]{43}$/.test(token),
        tokenAbsentFromDom: !renderedText.includes(token),
        tokenAbsentFromInspector: !inspectorText.includes(token),
        tokenAbsentFromStorage: !storageText.includes(token),
        tokenAbsentFromUrl: !location.href.includes(token),
        requiredCopy: [
          "Create session",
          "Revoke session",
          "Session active for this browser tab",
          "Advanced requests include a session header at send time",
          "Session token is never shown or saved",
        ].every((text) => renderedText.includes(text) || document.documentElement.outerHTML.includes(text)),
      };
    });

    if (
      surface.methods.join(",") !==
        "attachSessionHeader,create,current,ensureActive,getSnapshot,revoke,subscribe" ||
      surface.active !== true ||
      surface.phase !== "active" ||
      surface.panelPhase !== "active" ||
      !surface.status.includes("Session active for this browser tab") ||
      surface.tokenShape !== true ||
      surface.tokenAbsentFromDom !== true ||
      surface.tokenAbsentFromInspector !== true ||
      surface.tokenAbsentFromStorage !== true ||
      surface.tokenAbsentFromUrl !== true ||
      surface.requiredCopy !== true
    ) {
      throw new Error(`Advanced session public contract failed: ${JSON.stringify(surface)}`);
    }

    await page.locator("#advancedSessionRevokeBtn").click();
    await waitForPageCondition(
      "advanced session revokes locally",
      () => {
        const snapshot = window.XferryApp.service("advanced-session").getSnapshot();
        return snapshot.active === false &&
          document.getElementById("advancedSessionPanel")?.dataset.sessionPhase === "inactive";
      },
      null,
      10000
    );
    return surface;
  }

  async function assertOpsecQuickFlowUx() {
    await page.locator("#tab-opsec").click();
    await waitForTabState("opsec", { focused: true });
    await switchLanguage("en");

    await waitForPageCondition(
      "opsec quick flow defaults",
      () => {
        const quickSteps = Array.from(document.querySelectorAll("#opsec-tab [data-opsec-flow-step]"))
          .map((element) => element.getAttribute("data-opsec-flow-step"));
        const advanced = document.getElementById("opsecSettingsDetails");
        const outcome = document.querySelector('[data-testid="opsec-outcome-summary"]');
        const expertControls = [
          document.getElementById("opsecCarrierSelect"),
          document.getElementById("opsecMethodOverrideSelect"),
          document.getElementById("opsecBodyFormatSelect"),
          document.getElementById("opsecEncodingSelect"),
          document.getElementById("opsecMimeInput"),
          document.getElementById("opsecEncryptionSelect"),
          document.getElementById("opsecFilenamePrimarySelect"),
          document.getElementById("opsecFilenameCopies"),
        ];

        return Boolean(
          quickSteps.join(",") === "endpoint,profile,file" &&
          advanced &&
          advanced.dataset.testid === "opsec-advanced-options" &&
          advanced.open === false &&
          outcome &&
          outcome.innerText.includes("Resulting request") &&
          outcome.innerText.includes("Body · JSON") &&
          outcome.innerText.includes("base64") &&
          outcome.innerText.includes("uploads/") &&
          document.getElementById("opsecConstructorMode")?.value === "managed" &&
          document.getElementById("opsecProfileSelect")?.value === "body-json" &&
          expertControls.every((control) => control && advanced.contains(control))
        );
      },
      null,
      10000
    );

    await page.locator("#opsecSettingsDetails > summary").click();
    await waitForPageCondition(
      "opsec advanced options expand",
      () => {
        const advanced = document.getElementById("opsecSettingsDetails");
        const encoding = document.getElementById("opsecEncodingSelect");
        const primary = document.getElementById("opsecFilenamePrimarySelect");
        return Boolean(
          advanced &&
          advanced.open &&
          encoding &&
          encoding.getBoundingClientRect().height > 0 &&
          primary &&
          primary.value === "hidden" &&
          document.querySelector('label[for="opsecCarrierSelect"]') &&
          document.querySelector('label[for="opsecMimeInput"]')
        );
      },
      null,
      10000
    );

    await page.locator("#opsecCarrierSelect").selectOption("query");
    await waitForPageCondition(
      "managed carrier normalization is visible",
      () => {
        const items = document.getElementById("opsecNormalizationList");
        return Boolean(
          document.getElementById("opsecCarrierSelect")?.value === "body" &&
          items &&
          /carrier.*query.*body/i.test(items.textContent || "")
        );
      },
      null,
      10000
    );

    await page.locator("#opsecSettingsDetails > summary").click();
    await waitForPageCondition(
      "opsec advanced options collapse",
      () => document.getElementById("opsecSettingsDetails")?.open === false,
      null,
      10000
    );
  }

  async function assertOpsecPasswordValidationAccessibility(fixturePath) {
    await page.locator("#tab-opsec").click();
    await waitForTabState("opsec", { focused: true });
    await switchLanguage("en");
    await page.locator("#opsecFileInput").setInputFiles(fixturePath);
    await waitForPageCondition(
      "advanced upload is ready for password validation",
      () => {
        const button = document.getElementById("opsecUploadBtn");
        return Boolean(button && !button.disabled);
      }
    );

    if (!(await page.locator("#opsecSettingsDetails").evaluate((details) => details.open))) {
      await page.locator("#opsecSettingsDetails > summary").click();
    }
    await page.locator("#opsecEncryptionSelect").selectOption("xor");
    await page.locator("#opsecPassword").fill("");
    await page.locator("#opsecUploadBtn").click();
    await waitForPageCondition(
      "advanced password error identifies and focuses field",
      () => {
        const details = document.getElementById("opsecSettingsDetails");
        const password = document.getElementById("opsecPassword");
        const error = document.getElementById("opsecPasswordError");
        const describedBy = String(password?.getAttribute("aria-describedby") || "").split(/\s+/);
        return Boolean(
          details?.open &&
          password &&
          error &&
          document.activeElement === password &&
          password.getAttribute("aria-invalid") === "true" &&
          describedBy.includes("opsecEncryptionHelp") &&
          describedBy.includes("opsecPasswordError") &&
          error.hidden === false &&
          error.textContent?.includes("enter a password")
        );
      },
      null,
      10000
    );

    await page.locator("#opsecPassword").fill("browser-smoke-xor-key");
    await waitForPageCondition(
      "advanced password error clears on input",
      () => {
        const password = document.getElementById("opsecPassword");
        const error = document.getElementById("opsecPasswordError");
        return Boolean(
          password?.getAttribute("aria-invalid") === "false" &&
          error?.hidden === true
        );
      }
    );

    await page.locator("#opsecPassword").fill("");
    await page.locator("#opsecEncryptionSelect").selectOption("none");
    await page.locator("#opsecFileInput").setInputFiles([]);
  }

  async function assertUploadHelpUx() {
    await waitForTabState("upload", { focused: true });

    await waitForPageCondition(
      "upload profile and request summary defaults",
      () => {
        const profiles = Array.from(
          document.querySelectorAll("#uploadProfileGroup [data-upload-profile]")
        );
        const summary = document.getElementById("uploadRequestSummary");
        const requestLine = summary?.querySelector('[data-upload-summary="request-line"]');
        const bodyKind = summary?.querySelector('[data-upload-summary="body-kind"]');
        const mime = summary?.querySelector('[data-upload-summary="mime"]');
        const filenameSource = summary?.querySelector('[data-upload-summary="filename-source"]');
        return Boolean(
          profiles.map((button) => button.dataset.uploadProfile).join(",") ===
            "multipart,raw-url,raw-header" &&
          profiles[0]?.getAttribute("aria-checked") === "true" &&
          profiles[0]?.tabIndex === 0 &&
          profiles.slice(1).every((button) => (
            button.getAttribute("aria-checked") === "false" && button.tabIndex === -1
          )) &&
          summary?.getClientRects().length > 0 &&
          requestLine?.textContent?.includes("POST /uploads") &&
          /multipart/i.test(bodyKind?.textContent || "") &&
          mime?.textContent?.includes("application/octet-stream") &&
          (filenameSource?.textContent || "").trim().length > 0 &&
          !document.getElementById("uploadHelpDetails") &&
          !document.querySelector("#upload-tab .upload-flow-strip")
        );
      },
      null,
      10000
    );
    await assertVisibleUploadMethodComposer("upload methods visible at first render");
  }

  async function uploadOpsecViaUiAndAssertMethodStable(fixturePath) {
    await page.locator("#tab-opsec").click();
    await waitForTabState("opsec", { focused: true });
    await switchLanguage("en");
    await openToolTrace("opsec");
    await page.locator("#opsecConstructorMode").selectOption("managed");
    await page.locator("#opsecProfileSelect").selectOption("body-json");

    await page.locator("#opsecMethodInput").fill("CHECKDATA");
    await page.locator("#opsecFileInput").setInputFiles(fixturePath);
    await waitForPageCondition(
      "opsec upload button enabled",
      () => {
        const button = document.getElementById("opsecUploadBtn");
        return Boolean(button && !button.disabled);
      },
      null,
      10000
    );

    await waitForPageCondition(
      "opsec request preview omits no-gzip header by default",
      () => {
        const area = document.getElementById("opsecRequestArea");
        const text = area?.innerText || area?.textContent || "";
        const button = document.querySelector('[data-exchange-download-area="opsecRequestArea"]');
        return Boolean(
          area &&
          area.dataset.exchangePhase === "ready" &&
          /CHECKDATA\s+\/[^\s]+\s+HTTP\/1\.1/.test(text) &&
          text.includes("Content-Type: application/json") &&
          !text.includes("X-Exphttp-No-Gzip: 1") &&
          !text.includes("X-XFerry-No-Gzip: 1") &&
          button &&
          !button.disabled
        );
      },
      null,
      10000
    );

    await page.locator("#tab-upload").click();
    await waitForTabState("upload", { focused: true });
    await page.locator("#responseNoGzip").check();
    await page.locator("#tab-opsec").click();
    await waitForTabState("opsec", { focused: true });
    await waitForPageCondition(
      "opsec request preview includes canonical no-gzip header when enabled",
      () => {
        const text = document.getElementById("opsecRequestArea")?.innerText || "";
        return text.includes("X-XFerry-No-Gzip: 1") &&
          !text.includes("X-Exphttp-No-Gzip: 1");
      },
      null,
      10000
    );
    const opsecPreviewPath = await page.evaluate(() => {
      const text = document.getElementById("opsecRequestArea")?.innerText || "";
      return (text.match(/CHECKDATA\s+(\/[^\s]+)\s+HTTP\/1\.1/) || [])[1] || "";
    });
    if (!opsecPreviewPath) {
      throw new Error("Opsec preview path was not captured before upload");
    }
    await assertExchangeDownload(
      "opsecRequestArea",
      [
        `CHECKDATA ${opsecPreviewPath} HTTP/1.1`,
        'Content-Type: application/json',
        'X-XFerry-No-Gzip: 1',
        '"data":"[redacted]"',
        '"encoding":"base64"',
        '"encryption":"none"',
      ],
      /^xferry-opsec-request-.*\.http$/,
      ["QUFBQUFBQUFB"]
    );

    await page.locator("#opsecUploadBtn").click();
    await waitForPageCondition(
      "opsec upload completes",
      () => {
        const result = document.querySelector("[data-tool-summary-scope='opsec']");
        const outcomeMethod = document.querySelector("[data-opsec-outcome='method']");
        const resultText = result?.innerText || result?.textContent || "";
        return Boolean(
          result &&
          result.dataset.phase === "complete" &&
          /Advanced upload completed|Продвинутая загрузка выполнена/.test(resultText) &&
          resultText.includes("CHECKDATA") &&
          outcomeMethod?.textContent?.trim() === "CHECKDATA"
        );
      },
      null,
      15000
    );
    await waitForPageCondition(
      "opsec preview path matches sent request",
      ([expectedPath]) => {
        const text = document.getElementById("opsecRequestArea")?.innerText || "";
        return text.includes(`CHECKDATA ${expectedPath} HTTP/1.1`);
      },
      [opsecPreviewPath],
      10000
    );
    await assertExchangeDownload(
      "opsecResponseArea",
      ["HTTP/1.1 201 Created", '"file"', '"kind":"advanced"'],
      /^xferry-opsec-response-.*\.http$/
    );

    const opsecMethodConsistency = await page.evaluate(() => {
      const resultText = document.querySelector("[data-tool-summary-scope='opsec']")?.innerText || "";
      const outcomeMethod = document.querySelector("[data-opsec-outcome='method']")?.textContent?.trim() || "";
      const match = resultText.match(/Method\s+([A-Z]+)/i) || resultText.match(/Метод\s+([A-Z]+)/i);
      return {
        resultMethod: match ? match[1] : "",
        outcomeMethod,
      };
    });
    if (
      opsecMethodConsistency.resultMethod &&
      opsecMethodConsistency.resultMethod !== opsecMethodConsistency.outcomeMethod
    ) {
      throw new Error(`Opsec method summary drifted after upload: ${JSON.stringify(opsecMethodConsistency)}`);
    }

    return opsecMethodConsistency;
  }

  async function installNotepadWsActionRecorder() {
    await page.evaluate(() => {
      if (typeof window.__xferryRestoreNotepadWsActionRecorder === "function") {
        window.__xferryRestoreNotepadWsActionRecorder();
      }

      const NativeWebSocket = window.WebSocket;
      const actions = [];
      const record = (direction, raw, socketUrl) => {
        if (!String(socketUrl || "").includes("/notes/ws")) {
          return;
        }
        let msg;
        try {
          msg = JSON.parse(String(raw));
        } catch (error) {
          return;
        }
        if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
          return;
        }

        const input = msg.input;
        const inputKeys = input && typeof input === "object" && !Array.isArray(input)
          ? Object.keys(input).sort()
          : [];
        const frameKeys = Object.keys(msg).sort();
        const safeDirection = direction === "sent"
          ? { direction: "sent" }
          : { direction: "received" };
        actions.push({
          ...safeDirection,
          action: typeof msg.action === "string" ? msg.action : "",
          request_id: typeof msg.request_id === "string" ? msg.request_id : "",
          inputKeys,
          frameKeys,
        });
      };

      const RecordingWebSocket = new Proxy(NativeWebSocket, {
        get(target, property, receiver) {
          if (
            property === "CONNECTING" ||
            property === "OPEN" ||
            property === "CLOSING" ||
            property === "CLOSED"
          ) {
            return target[property];
          }
          return Reflect.get(target, property, receiver);
        },
        construct(target, args) {
          const socket = Reflect.construct(target, args, target);
          const socketUrl = args[0];
          socket.addEventListener("message", event => {
            record("received", event.data, socketUrl);
          });
          return new Proxy(socket, {
            get(socketTarget, property) {
              if (property === "send") {
                return data => {
                  record("sent", data, socketUrl);
                  return socketTarget.send(data);
                };
              }
              const value = Reflect.get(socketTarget, property, socketTarget);
              return typeof value === "function" ? value.bind(socketTarget) : value;
            },
            set(socketTarget, property, value) {
              socketTarget[property] = value;
              return true;
            },
          });
        },
      });

      window.__xferryNotepadWsActions = actions;
      window.WebSocket = RecordingWebSocket;
      window.__xferryRestoreNotepadWsActionRecorder = () => {
        if (window.WebSocket === RecordingWebSocket) {
          window.WebSocket = NativeWebSocket;
        }
        delete window.__xferryRestoreNotepadWsActionRecorder;
      };
    });
  }

  async function assertNotepadWsActionCoverage() {
    const coverage = await page.evaluate(() => {
      const actions = Array.isArray(window.__xferryNotepadWsActions)
        ? window.__xferryNotepadWsActions
        : [];
      const sent = actions.filter(action => action.direction === "sent");
      const received = actions.filter(action => action.direction === "received");
      const sentCounts = {
        load: sent.filter(action => action.action === "load").length,
        delete: sent.filter(action => action.action === "delete").length,
        clear: sent.filter(action => action.action === "clear").length,
      };
      const receivedCounts = {
        load: received.filter(action => action.action === "load").length,
        delete: received.filter(action => action.action === "delete").length,
        clear: received.filter(action => action.action === "clear").length,
      };
      const requestIdPattern = /^[A-Za-z0-9._:-]{1,128}$/;
      const targetActions = new Set(["load", "delete", "clear"]);
      const invalid = actions.filter(action => {
        if (!targetActions.has(action.action)) {
          return false;
        }
        if (!requestIdPattern.test(action.request_id || "")) {
          return true;
        }
        const inputKeys = Array.isArray(action.inputKeys) ? action.inputKeys : null;
        const frameKeys = Array.isArray(action.frameKeys) ? action.frameKeys : null;
        if (!inputKeys || !frameKeys) {
          return true;
        }
        const expectedInputKeys = action.direction === "sent" && action.action !== "clear"
          ? ["id"]
          : [];
        if (inputKeys.join(",") !== expectedInputKeys.join(",")) {
          return true;
        }
        if (action.direction === "sent") {
          return frameKeys.join(",") !== "action,input,request_id";
        }
        return ![
          "action,request_id,result",
          "action,error,request_id",
        ].includes(frameKeys.join(","));
      });
      return {
        total: actions.length,
        sentCounts,
        receivedCounts,
        invalidCount: invalid.length,
      };
    });

    if (
      coverage.invalidCount !== 0 ||
      coverage.sentCounts.load <= 0 ||
      coverage.sentCounts.delete <= 0 ||
      coverage.sentCounts.clear <= 0 ||
      coverage.receivedCounts.load <= 0 ||
      coverage.receivedCounts.delete <= 0 ||
      coverage.receivedCounts.clear <= 0
    ) {
      throw new Error(`Notepad WebSocket action coverage failed: ${JSON.stringify(coverage)}`);
    }
    return coverage;
  }

  async function createAutosavedNote(title, text) {
    await page.locator("#notepadNewBtn").click();
    await page.locator("#notepadTitleInput").fill(title);
    await page.locator("#notepadTextarea").fill(text);
    try {
      await waitForText(page.locator("#notepadNoteList"), title, 15000);
      await waitForText(page.locator("#notepadSaveIndicator"), /Сохранено|Saved/, 15000);
    } catch (error) {
      const indicator = (await page.locator("#notepadSaveIndicator").textContent() || "").trim();
      throw new Error(`createAutosavedNote(${title}) failed: indicator=${indicator}; ${error.message}`);
    }
  }

  async function assertNotepadDestructiveMethodStates(timeout = 10000) {
    await waitForPageCondition(
      "notepad destructive controls are available",
      () => {
        const deleteBtn = document.getElementById("notepadDeleteBtn");
        const selectedDeleteBtn = document.getElementById("notepadDeleteSelectedBtn");
        const clearBtn = document.getElementById("notepadClearBtn");
        const selectors = Array.from(document.querySelectorAll("[data-note-select]"));
        return Boolean(
          deleteBtn &&
          selectedDeleteBtn &&
          clearBtn &&
          !deleteBtn.disabled &&
          !clearBtn.disabled &&
          selectors.length > 0 &&
          selectors.every((selector) => !selector.disabled)
        );
      },
      null,
      timeout
    );
  }

  async function assertNotepadSaveErrorSurfacesDetail(originalText, timeout = 15000) {
    const detail = "Notepad storage quota exceeded. Browser smoke quota detail.";
    await page.evaluate(([targetDetail]) => {
      const http = window.XferryApp.service("http");
      let originalAdapter = null;
      const failingAdapter = async (method, url, body, headers = {}) => {
        if (method === "NOTE" && String(url).endsWith("/notes?action=save") && body) {
          return new Response(
            JSON.stringify({ error: {
              code: "payload_too_large",
              message: targetDetail,
              field: "data",
              details: { scope: "note", limit_bytes: 1048576 },
            } }),
            {
              status: 413,
              statusText: "Payload Too Large",
              headers: { "Content-Type": "application/json" },
            }
          );
        }
        return originalAdapter(method, url, body, headers);
      };
      originalAdapter = http["set-adapter"](failingAdapter);
      window.__xferryOriginalHttpAdapter = originalAdapter;
    }, [detail]);

    try {
      await page.locator("#notepadTextarea").fill(`${originalText}\nquota failure probe`);
      await waitForText(page.locator("#notepadSaveIndicator"), detail, timeout);
    } finally {
      await page.evaluate(() => {
        if (window.__xferryOriginalHttpAdapter) {
          window.XferryApp
            .service("http")
            ["set-adapter"](window.__xferryOriginalHttpAdapter);
          delete window.__xferryOriginalHttpAdapter;
        }
      });
    }

    await page.locator("#notepadTextarea").fill(originalText);
    await waitForText(page.locator("#notepadSaveIndicator"), /Сохранено|Saved/, timeout);
  }

  async function clickNoteByTitle(title) {
    await page.locator(".note-item", { hasText: title }).click();
    await waitForValue("#notepadTitleInput", title);
  }

  async function assertDirtyTransitionFlushes() {
    const sourceTitle = "Browser Smoke Dirty Source";
    const targetTitle = "Browser Smoke Dirty Target";
    const sourceOriginal = "dirty transition original body";
    const targetText = "dirty transition target body";
    const sourceEditedForSwitch = "dirty edit saved before note switch";
    const sourceEditedForNew = "dirty edit saved before new note";

    await createAutosavedNote(sourceTitle, sourceOriginal);
    await createAutosavedNote(targetTitle, targetText);
    await clickNoteByTitle(sourceTitle);

    await page.locator("#notepadTextarea").fill(sourceEditedForSwitch);
    await page.locator(".note-item", { hasText: targetTitle }).click();
    await waitForValue("#notepadTitleInput", targetTitle, 15000);
    await clickNoteByTitle(sourceTitle);
    await waitForValue("#notepadTextarea", sourceEditedForSwitch, 15000);

    await page.locator("#notepadTextarea").fill(sourceEditedForNew);
    await page.locator("#notepadNewBtn").click();
    await waitForValue("#notepadTitleInput", "", 15000);
    await clickNoteByTitle(sourceTitle);
    await waitForValue("#notepadTextarea", sourceEditedForNew, 15000);

    return {
      sourceTitle,
      targetTitle,
      sourceEditedForSwitch,
      sourceEditedForNew,
    };
  }

  async function assertStaleLoadDoesNotOverwriteDirtyDraft() {
    const targetTitle = "Browser Smoke Stale Load Target";
    const targetText = "stale load target body";
    const draftTitle = "Browser Smoke Race Dirty Draft";
    const draftText = "draft typed while note load is pending";

    await createAutosavedNote(targetTitle, targetText);
    const encodedTargetId = await page.locator(".note-item", { hasText: targetTitle }).getAttribute("data-note-id");
    if (!encodedTargetId) {
      throw new Error(`Could not resolve note id for ${targetTitle}`);
    }
    await page.locator("#notepadNewBtn").click();
    await waitForValue("#notepadTitleInput", "", 15000);

    await page.evaluate(([id]) => {
      const http = window.XferryApp.service("http");
      let originalRequestAdapter = null;
      let releaseLoad = null;
      const delay = new Promise((resolve) => {
        releaseLoad = resolve;
      });

      window.__xferryReleaseStaleNoteLoad = () => {
        http["set-adapter"](originalRequestAdapter);
        releaseLoad();
      };

      const delayedAdapter = async (...args) => {
        const [method, url] = args;
        if (method === "NOTE" && String(url).includes(`/notes/${id}`)) {
          await delay;
        }
        return originalRequestAdapter(...args);
      };
      originalRequestAdapter = http["set-adapter"](delayedAdapter);
    }, [decodeURIComponent(encodedTargetId)]);

    await page.locator(".note-item", { hasText: targetTitle }).click();
    await waitForText(page.locator("#notepadSaveIndicator"), /Загрузка|Loading/, 15000);
    await page.locator("#notepadNewBtn").click();
    await waitForValue("#notepadTitleInput", "", 15000);
    await page.locator("#notepadTitleInput").fill(draftTitle);
    await page.locator("#notepadTextarea").fill(draftText);
    await waitForPageCondition(
      "draft is dirty while load is pending",
      () => document.body.classList.contains("notepad-dirty"),
      null,
      10000
    );

    await page.evaluate(() => window.__xferryReleaseStaleNoteLoad());
    await page.waitForTimeout(500);
    await waitForValue("#notepadTitleInput", draftTitle, 15000);
    await waitForValue("#notepadTextarea", draftText, 15000);

    return {
      targetTitle,
      draftTitle,
    };
  }

  async function assertWsLostAckRetryIsIdempotent() {
    const title = "Browser Smoke WS Lost Ack";
    const text = "websocket first save retry body";

    await page.locator('input[name="notepadTransport"][value="http"]').check();
    await waitForConnectionStatus("connected", "http", 15000);
    await page.locator("#notepadNewBtn").click();
    await waitForValue("#notepadTitleInput", "", 15000);

    await page.evaluate(() => {
      if (typeof window.__xferryRestoreNotepadWebSocket === "function") {
        window.__xferryRestoreNotepadWebSocket();
      }

      const NativeWebSocket = window.WebSocket;
      window.__xferryDroppedFirstWsSaveAck = 0;

      function DroppingWebSocket(...args) {
        const socket = new NativeWebSocket(...args);
        let onmessageHandler = null;

        socket.addEventListener("message", (event) => {
          let shouldDrop = false;
          try {
            const msg = JSON.parse(event.data);
            shouldDrop = Boolean(
              msg &&
              msg.action === "save" &&
              msg.request_id &&
              msg.result &&
              msg.result.note &&
              window.__xferryDroppedFirstWsSaveAck === 0
            );
          } catch (error) {
            shouldDrop = false;
          }

          if (shouldDrop) {
            window.__xferryDroppedFirstWsSaveAck = 1;
            setTimeout(() => socket.close(), 0);
            return;
          }

          if (typeof onmessageHandler === "function") {
            onmessageHandler.call(socket, event);
          }
        });

        return new Proxy(socket, {
          get(target, prop) {
            if (prop === "onmessage") {
              return onmessageHandler;
            }
            const value = target[prop];
            return typeof value === "function" ? value.bind(target) : value;
          },
          set(target, prop, value) {
            if (prop === "onmessage") {
              onmessageHandler = value;
              return true;
            }
            target[prop] = value;
            return true;
          },
        });
      }

      Object.defineProperties(DroppingWebSocket, {
        CONNECTING: { value: NativeWebSocket.CONNECTING },
        OPEN: { value: NativeWebSocket.OPEN },
        CLOSING: { value: NativeWebSocket.CLOSING },
        CLOSED: { value: NativeWebSocket.CLOSED },
      });

      window.WebSocket = DroppingWebSocket;
      window.__xferryRestoreNotepadWebSocket = () => {
        window.WebSocket = NativeWebSocket;
        delete window.__xferryRestoreNotepadWebSocket;
      };
    });

    try {
      await page.locator('input[name="notepadTransport"][value="ws"]').check();
      await waitForConnectionStatus("connected", "ws", 15000);
      await page.locator("#notepadTitleInput").fill(title);
      await page.locator("#notepadTextarea").fill(text);
      await waitForText(page.locator("#notepadSaveIndicator"), /Сохранено|Saved/, 20000);
      await waitForText(page.locator("#notepadNoteList"), title, 20000);
      await waitForConnectionStatus("connected", "ws", 20000);
      await waitForPageCondition(
        "ws lost ack retry is idempotent",
        ([targetTitle]) => {
          const titles = Array.from(document.querySelectorAll(".note-item-title"))
            .map((element) => element.textContent.trim())
            .filter((value) => value === targetTitle);
          const indicator = document.getElementById("notepadSaveIndicator");
          return Boolean(
            window.__xferryDroppedFirstWsSaveAck === 1 &&
            titles.length === 1 &&
            indicator &&
            /Сохранено|Saved/.test(indicator.innerText) &&
            !document.body.classList.contains("notepad-dirty")
          );
        },
        [title],
        20000
      );
    } finally {
      await page.evaluate(() => {
        if (typeof window.__xferryRestoreNotepadWebSocket === "function") {
          window.__xferryRestoreNotepadWebSocket();
        }
      });
    }

    return { title };
  }

  async function clearNotesViaUiAndAssert(uploadPathToPreserve) {
    const uploadNameToPreserve = uploadPathToPreserve.split("/").pop();

    await page.locator("#notepadClearBtn").click();
    await confirmAppDialog(/notes\//, 10000);
    await waitForPageCondition(
      "notepad notes cleared",
      () => {
        const titleInput = document.getElementById("notepadTitleInput");
        const textarea = document.getElementById("notepadTextarea");
        const deleteBtn = document.getElementById("notepadDeleteBtn");
        const noteList = document.getElementById("notepadNoteList");
        const indicator = document.getElementById("notepadSaveIndicator");
        const refreshBtn = document.getElementById("notepadRefreshBtn");
        return Boolean(
          titleInput &&
          textarea &&
          deleteBtn &&
          noteList &&
          indicator &&
          refreshBtn &&
          titleInput.value === "" &&
          textarea.value === "" &&
          deleteBtn.disabled &&
          /Нет заметок|No notes/.test(noteList.innerText) &&
          /Заметки очищены|Notes cleared/.test(indicator.innerText) &&
          document.activeElement === refreshBtn
        );
      },
      null,
      15000
    );

    await browseUploadsAndAssert(uploadNameToPreserve);
    return uploadPathToPreserve;
  }

  async function deleteSelectedUploadViaUiAndAssert(path) {
    const name = path.split("/").pop();
    const encodedPath = encodeURIComponent(path);

    await browseUploadsAndAssert(name);
    await page.locator(`#serverFiles [data-file-select][data-path="${encodedPath}"]`).check();
    await page.evaluate(() => {
      const previous = window.__filesBulkDeleteToastFocusContract;
      if (previous?.listener) {
        document.removeEventListener("focusin", previous.listener, true);
      }
      const contract = { toastFocusEvents: [], listener: null };
      contract.listener = (event) => {
        const target = event.target;
        if (target instanceof Element && target.closest("[data-files-toast]")) {
          contract.toastFocusEvents.push({
            tagName: target.tagName,
            className: target.className,
          });
        }
      };
      document.addEventListener("focusin", contract.listener, true);
      window.__filesBulkDeleteToastFocusContract = contract;
    });

    try {
      await page.locator("#deleteSelectedUploadsBtn").click();
      await confirmAppDialog(path, 10000);
      await waitForPageCondition(
        `selected upload deleted (${name})`,
        ([targetPath]) => !document.querySelector(`#serverFiles [data-path="${targetPath}"]`),
        [encodedPath],
        15000
      );

      const expectedToastMessage = await page.evaluate(() => (
        document.documentElement.lang.toLowerCase().startsWith("en")
          ? "Selected files deleted: 1"
          : "Выбранные файлы удалены: 1"
      ));
      await waitForPageCondition(
        `selected upload success toast is stable (${name})`,
        ([expectedMessage]) => {
          const toast = document.querySelector("#filesToastRegion [data-files-toast]");
          const message = toast?.querySelector("[data-files-toast-message]");
          const live = document.getElementById("filesToastLive");
          const summary = document.querySelector('[data-tool-summary-scope="files"]');
          const focusContract = window.__filesBulkDeleteToastFocusContract;
          return Boolean(
            toast &&
            message?.textContent?.trim() === expectedMessage &&
            live?.textContent?.trim() === expectedMessage &&
            document.activeElement?.id === "browsePathInput" &&
            !toast.contains(document.activeElement) &&
            focusContract?.toastFocusEvents.length === 0 &&
            summary?.dataset.phase === "empty"
          );
        },
        [expectedToastMessage],
        15000
      );

      const toastSnapshot = await page.evaluate(([expectedMessage]) => {
        const region = document.getElementById("filesToastRegion");
        const toast = region?.querySelector("[data-files-toast]");
        const message = toast?.querySelector("[data-files-toast-message]");
        const dismiss = toast?.querySelector("[data-files-toast-dismiss]");
        const summary = document.querySelector('[data-tool-summary-scope="files"]');
        const regionStyle = region ? getComputedStyle(region) : null;
        const toastRect = toast?.getBoundingClientRect();
        const dismissRect = dismiss?.getBoundingClientRect();
        return {
          expectedMessage,
          message: message?.textContent?.trim() || "",
          liveMessage: document.getElementById("filesToastLive")?.textContent?.trim() || "",
          regionPosition: regionStyle?.position || "",
          toastRect: toastRect ? {
            left: toastRect.left,
            top: toastRect.top,
            right: toastRect.right,
            bottom: toastRect.bottom,
            width: toastRect.width,
            height: toastRect.height,
          } : null,
          dismissRect: dismissRect ? {
            width: dismissRect.width,
            height: dismissRect.height,
          } : null,
          dismissLabel: dismiss?.getAttribute("aria-label") || "",
          viewport: { width: innerWidth, height: innerHeight },
          activeElementId: document.activeElement?.id || "",
          toastContainsFocus: Boolean(toast?.contains(document.activeElement)),
          toastFocusEvents: (
            window.__filesBulkDeleteToastFocusContract?.toastFocusEvents || []
          ).slice(),
          summaryPhase: summary?.dataset.phase || "",
        };
      }, [expectedToastMessage]);
      const toastRect = toastSnapshot.toastRect;
      const dismissRect = toastSnapshot.dismissRect;
      const rightGap = toastRect
        ? toastSnapshot.viewport.width - toastRect.right
        : Number.POSITIVE_INFINITY;
      const bottomGap = toastRect
        ? toastSnapshot.viewport.height - toastRect.bottom
        : Number.POSITIVE_INFINITY;
      if (
        toastSnapshot.message !== expectedToastMessage ||
        toastSnapshot.liveMessage !== expectedToastMessage ||
        toastSnapshot.regionPosition !== "fixed" ||
        !toastRect ||
        toastRect.width <= 0 ||
        toastRect.height <= 0 ||
        toastRect.left < -1 ||
        toastRect.top < -1 ||
        toastRect.right > toastSnapshot.viewport.width + 1 ||
        toastRect.bottom > toastSnapshot.viewport.height + 1 ||
        rightGap < -1 ||
        rightGap > 64 ||
        bottomGap < -1 ||
        bottomGap > 64 ||
        toastRect.right < toastSnapshot.viewport.width / 2 ||
        toastRect.bottom < toastSnapshot.viewport.height / 2 ||
        !dismissRect ||
        dismissRect.width < 43.5 ||
        dismissRect.height < 43.5 ||
        !toastSnapshot.dismissLabel ||
        toastSnapshot.activeElementId !== "browsePathInput" ||
        toastSnapshot.toastContainsFocus ||
        toastSnapshot.toastFocusEvents.length !== 0 ||
        toastSnapshot.summaryPhase !== "empty"
      ) {
        throw new Error(
          `Files bulk-delete toast contract failed: ${JSON.stringify({ ...toastSnapshot, rightGap, bottomGap })}`
        );
      }

      await page.evaluate(() => {
        const contract = window.__filesBulkDeleteToastFocusContract;
        if (contract?.listener) {
          document.removeEventListener("focusin", contract.listener, true);
          contract.listener = null;
        }
      });
      const dismissButton = page.locator("#filesToastRegion [data-files-toast-dismiss]");
      await dismissButton.focus();
      await waitForPageCondition(
        `selected upload toast dismiss target receives deliberate focus (${name})`,
        () => document.activeElement?.matches("[data-files-toast-dismiss]") === true,
        null,
        10000
      );
      await dismissButton.click();
      await waitForPageCondition(
        `selected upload toast dismiss restores stable focus (${name})`,
        () => {
          const summary = document.querySelector('[data-tool-summary-scope="files"]');
          return Boolean(
            !document.querySelector("#filesToastRegion [data-files-toast]") &&
            document.activeElement?.id === "browsePathInput" &&
            summary?.dataset.phase === "empty"
          );
        },
        null,
        10000
      );
    } finally {
      await page.evaluate(() => {
        const contract = window.__filesBulkDeleteToastFocusContract;
        if (contract?.listener) {
          document.removeEventListener("focusin", contract.listener, true);
        }
        delete window.__filesBulkDeleteToastFocusContract;
      });
    }
  }

  async function activateFilesAndWaitForSettledBrowse() {
    const browseGenerationBeforeActivation = await page.evaluate(() => (
      window.XferryApp.getState("files")?.browseGeneration ?? -1
    ));
    await page.locator("#tab-files").click();
    await waitForTabState("files", { focused: true });
    await waitForPageCondition(
      "files browse settles after Files workspace activation",
      ([previousGeneration]) => {
        const filesState = window.XferryApp.getState("files");
        const browseStatus = document.getElementById("filesBrowseStatus");
        const list = document.getElementById("serverFiles");
        return Boolean(
          Number.isInteger(filesState?.browseGeneration) &&
          filesState.browseGeneration > previousGeneration &&
          ["complete", "empty"].includes(browseStatus?.dataset.browsePhase || "") &&
          list?.getAttribute("aria-busy") === "false"
        );
      },
      [browseGenerationBeforeActivation],
      15000
    );
  }

  async function clearUploadsViaUiAndAssertSummaryPersistence() {
    await activateFilesAndWaitForSettledBrowse();
    await openFilesGlobalActions();
    await page.locator("#clearUploadsBtn").evaluate((button) => button.click());
    const clearRequestPromise = page.waitForRequest(
      (request) => request.method() === "DELETE" && /\/uploads(?:\?|$)/.test(request.url()),
      { timeout: 10000 }
    );
    await confirmAppDialog(/uploads\//, 10000);
    const clearRequest = await clearRequestPromise;
    const clearRequestTarget = clearRequest.url().replace(/^https?:\/\/[^/]+/, "");
    if (clearRequestTarget !== "/uploads?clear=true") {
      throw new Error(`Files clear request target is not strict: ${clearRequestTarget}`);
    }
    await waitForPageCondition(
      "clear uploads lands on an empty root listing",
      () => {
        const pathInput = document.getElementById("browsePathInput");
        const browseStatus = document.getElementById("filesBrowseStatus");
        const list = document.getElementById("serverFiles");
        const summaryRoot = document.querySelector('[data-tool-summary-scope="files"]');
        const emptyText = (list?.innerText || list?.textContent || "").trim();
        return Boolean(
          pathInput?.value === "/" &&
          browseStatus?.dataset.browsePhase === "complete" &&
          (browseStatus?.innerText || browseStatus?.textContent || "").includes("/") &&
          list?.getAttribute("aria-busy") === "false" &&
          (/В этой папке нет файлов|There are no files in this folder/i.test(emptyText)) &&
          (!summaryRoot || ["complete", "empty"].includes(summaryRoot.dataset.phase || ""))
        );
      },
      null,
      15000
    );
  }

  async function openFilesGlobalActions(timeout = 10000) {
    const globalActions = page.locator("#filesGlobalActions");
    const summary = page.locator("#filesGlobalActions > summary");
    await globalActions.waitFor({ state: "visible", timeout });
    if (!await globalActions.evaluate((element) => element.open)) {
      await summary.click();
      await waitForPageCondition(
        "files global actions opens",
        () => document.getElementById("filesGlobalActions")?.open === true,
        null,
        timeout
      );
    }
    return { globalActions, summary };
  }

  async function assertClearUploadsGlobalActionsAndRetryConfirmation() {
    await activateFilesAndWaitForSettledBrowse();
    const globalActions = page.locator("#filesGlobalActions");
    const globalSummary = page.locator("#filesGlobalActions > summary");
    const clearButton = page.locator("#clearUploadsBtn");
    await globalActions.waitFor({ state: "visible", timeout: 10000 });
    if (await page.locator("#filesDangerZone").count()) {
      throw new Error("Clear uploads old danger zone is still mounted");
    }
    if (await globalActions.evaluate((element) => element.open)) {
      throw new Error("Clear uploads global actions menu must start collapsed");
    }
    if (await clearButton.isVisible()) {
      throw new Error("Clear uploads control is visible outside its collapsed global actions menu");
    }

    await globalSummary.focus();
    await page.keyboard.press("Enter");
    await waitForPageCondition(
      "files global actions opens by keyboard",
      () => document.getElementById("filesGlobalActions")?.open === true,
      null,
      10000
    );
    await clearButton.focus();
    await clearButton.press("Enter");
    const dialog = page.locator('#appDialog [role="alertdialog"]');
    await dialog.waitFor({ state: "visible", timeout: 10000 });
    await waitForPageCondition(
      "clear uploads confirmation starts at Cancel",
      () => document.activeElement?.getAttribute("data-dialog-action") === "cancel",
      null,
      10000
    );
    await page.keyboard.press("Escape");
    await page.locator("#appDialog").waitFor({ state: "detached", timeout: 10000 });
    await waitForPageCondition(
      "clear uploads cancellation restores focus",
      () => document.activeElement?.id === "clearUploadsBtn",
      null,
      10000
    );

    await page.evaluate(() => {
      const http = window.XferryApp.service("http");
      window.__xferryClearUploadsAttempts = 0;
      window.__xferryClearUploadsAdapter = http["set-adapter"]((method, url) => {
        if (method === "DELETE" && String(url).includes("/uploads?clear=true")) {
          window.__xferryClearUploadsAttempts += 1;
          return Promise.resolve({
            ok: false,
            status: 503,
            statusText: "Service unavailable",
            headers: { "content-type": "application/json" },
            text: async () => JSON.stringify({ error: {
              code: "clear_unavailable", message: "clear unavailable", field: null, details: {},
            } }),
          });
        }
        throw new Error(`Unexpected clear uploads test request: ${method} ${url}`);
      });
    });
    try {
      await clearButton.click();
      await page.locator('#appDialog [data-dialog-action="confirm"]').click();
      const errorCard = page.locator("#filesHttpErrorHost .http-error-card");
      await errorCard.waitFor({ state: "visible", timeout: 10000 });
      await errorCard.locator('[data-http-error-action="retry"]').click();
      await dialog.waitFor({ state: "visible", timeout: 10000 });
      const attemptsBeforeReconfirm = await page.evaluate(() => window.__xferryClearUploadsAttempts);
      if (attemptsBeforeReconfirm !== 1) {
        throw new Error(`Clear uploads Retry bypassed confirmation: ${attemptsBeforeReconfirm}`);
      }
      await page.keyboard.press("Escape");
      await page.locator("#appDialog").waitFor({ state: "detached", timeout: 10000 });
      await waitForPageCondition(
        "clear uploads retry confirmation restores focus",
        () => document.activeElement?.matches("#filesGlobalActions > summary") === true,
        null,
        10000
      );
    } finally {
      await page.evaluate(() => {
        const http = window.XferryApp.service("http");
        http["set-adapter"](window.__xferryClearUploadsAdapter);
        delete window.__xferryClearUploadsAdapter;
        delete window.__xferryClearUploadsAttempts;
      });
    }
  }

  async function deleteSelectedNoteViaUiAndAssert(deleteTitle, keepTitle) {
    await page.locator(".note-row", { hasText: deleteTitle }).locator("[data-note-select]").check();
    await assertNotepadSelectedDeleteButtonState({
      disabled: false,
      count: 1,
      labelPrefix: "Удалить выбранные заметки",
    });
    await page.locator("#notepadDeleteSelectedBtn").click();
    await confirmAppDialog(deleteTitle, 10000);
    await waitForPageCondition(
      `selected note deleted (${deleteTitle})`,
      ([removedTitle, remainingTitle]) => {
        const noteList = document.getElementById("notepadNoteList");
        const titleInput = document.getElementById("notepadTitleInput");
        const textarea = document.getElementById("notepadTextarea");
        const refreshBtn = document.getElementById("notepadRefreshBtn");
        return Boolean(
          noteList &&
          titleInput &&
          textarea &&
          refreshBtn &&
          !noteList.innerText.includes(removedTitle) &&
          noteList.innerText.includes(remainingTitle) &&
          titleInput.value === "" &&
          textarea.value === "" &&
          document.activeElement === refreshBtn
        );
      },
      [deleteTitle, keepTitle],
      15000
    );
  }

  async function loadNoteByKeyboard(title) {
    await page.locator("#notepadRefreshBtn").focus();
    for (let i = 0; i < 12; i++) {
      await page.keyboard.press("Tab");
      const focused = await page.evaluate(([targetTitle]) => {
        const active = document.activeElement;
        return Boolean(
          active &&
          active.classList &&
          active.classList.contains("note-item") &&
          active.innerText.includes(targetTitle)
        );
      }, [title]);
      if (focused) {
        break;
      }
    }
    await waitForPageCondition(
      `note item focused (${title})`,
      ([targetTitle]) => {
        const active = document.activeElement;
        return Boolean(
          active &&
          active.classList &&
          active.classList.contains("note-item") &&
          active.textContent &&
          active.textContent.includes(targetTitle)
        );
      },
      [title],
      10000
    );
    const focusedNoteId = await page.evaluate(([targetTitle]) => {
      const active = document.activeElement;
      if (
        !active ||
        !active.classList ||
        !active.classList.contains("note-item") ||
        !active.textContent ||
        !active.textContent.includes(targetTitle)
      ) {
        return "";
      }
      return active.getAttribute("data-note-id") || "";
    }, [title]);
    if (!focusedNoteId) {
      throw new Error(`Could not resolve focused note id for ${title}`);
    }
    await page.evaluate(() => {
      window.XferryApp.invoke("notepad", "refresh-methods");
    });
    await waitForPageCondition(
      `note item focus preserved after refresh (${title})`,
      ([targetTitle, expectedNoteId]) => {
        const active = document.activeElement;
        return Boolean(
          active &&
          active.classList &&
          active.classList.contains("note-item") &&
          active.getAttribute("data-note-id") === expectedNoteId &&
          active.textContent &&
          active.textContent.includes(targetTitle)
        );
      },
      [title, focusedNoteId],
      10000
    );
    await page.keyboard.press("Enter");
    await waitForValue("#notepadTitleInput", title);
  }

  async function assertMobileLayoutSnapshot(timeout = 10000) {
    const currentUrl = page.url();
    const rootUrl = currentUrl.replace(/^(https?:\/\/[^/]+).*/, "$1/");
    await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => {
      const requestDetails = document.getElementById("requestTechnicalDetails");
      if (requestDetails) requestDetails.open = false;
    });
    await assertTopTabContract({ lang: "ru", viewportLabel: "mobile", expectedActive: "upload" });
    await page.locator("#tab-request").click();
    await waitForTabState("request", { focused: true });
    await page.evaluate(() => {
      const details = document.getElementById("requestTechnicalDetails");
      if (details) details.open = false;
    });
    await waitForPageCondition(
      "mobile request technical disclosure starts closed",
      () => document.getElementById("requestTechnicalDetails")?.open === false,
      null,
      timeout
    );
    if (await page.locator(".request-method-switch [data-request-method]").first().isVisible()) {
      throw new Error("Mobile request method control is visible while technical disclosure is closed");
    }
    await openRequestTechnicalDetails({ timeout });

    await waitForPageCondition(
      "mobile layout snapshot",
      () => {
        const doc = document.documentElement;
        const requestSwitch = document.querySelector(".request-method-switch");
        const modeTabs = document.querySelector(".mode-tabs");
        const requestPanel = document.querySelector(".request-panel");
        const heroResponse = document.querySelector(".response-area--hero");
        const exchangeGrid = document.querySelector(".exchange-inspector__grid");
        const exchangeScroll = document.querySelector(".exchange-inspector__scroll");
        const topbar = document.querySelector(".topbar");
        const stage = document.querySelector(".workspace-stage");

        if (
          !requestSwitch ||
          !modeTabs ||
          !requestPanel ||
          !heroResponse ||
          !exchangeGrid ||
          !exchangeScroll ||
          !topbar ||
          !stage
        ) {
          return false;
        }

        const countColumns = (trackList) => {
          const normalized = (trackList || "").trim();
          return normalized && normalized !== "none" ? normalized.split(/\s+/).length : 0;
        };

        const requestSwitchStyles = window.getComputedStyle(requestSwitch);
        const modeTabsStyles = window.getComputedStyle(modeTabs);
        const requestPanelStyles = window.getComputedStyle(requestPanel);
        const heroResponseStyles = window.getComputedStyle(heroResponse);
        const exchangeGridStyles = window.getComputedStyle(exchangeGrid);
        const modeTabsRect = modeTabs.getBoundingClientRect();
        const stageRect = stage.getBoundingClientRect();
        const modeTabButtons = Array.from(
          modeTabs.querySelectorAll(".tab[role=\"tab\"]:not([hidden])")
        );
        const modeTabsFit = modeTabButtons.length > 0 && modeTabButtons.every((button) => {
          const rect = button.getBoundingClientRect();
          return rect.left >= modeTabsRect.left - 1 && rect.right <= modeTabsRect.right + 1;
        });
        const modeTabsMeetTouchTarget = modeTabButtons.every((button) => {
          const rect = button.getBoundingClientRect();
          return rect.width >= 48 && rect.height >= 48;
        });

        return (
          doc.scrollWidth <= window.innerWidth + 1 &&
          countColumns(requestSwitchStyles.gridTemplateColumns) === 3 &&
          modeTabsStyles.display === "grid" &&
          countColumns(modeTabsStyles.gridTemplateColumns) === 2 &&
          modeTabs.scrollWidth <= modeTabs.clientWidth + 1 &&
          modeTabsFit &&
          modeTabsMeetTouchTarget &&
          countColumns(exchangeGridStyles.gridTemplateColumns) === 1 &&
          exchangeScroll.scrollWidth <= exchangeScroll.clientWidth + 1 &&
          parseFloat(requestPanelStyles.paddingTop) <= 16.5 &&
          parseFloat(heroResponseStyles.minHeight) <= 220.5 &&
          stageRect.top <= 390
        );
      },
      null,
      timeout
    );

    const snapshot = await page.evaluate(() => {
      const doc = document.documentElement;
      const requestSwitch = document.querySelector(".request-method-switch");
      const modeTabs = document.querySelector(".mode-tabs");
      const requestPanel = document.querySelector(".request-panel");
      const heroResponse = document.querySelector(".response-area--hero");
      const exchangeGrid = document.querySelector(".exchange-inspector__grid");
      const exchangeScroll = document.querySelector(".exchange-inspector__scroll");
      const topbar = document.querySelector(".topbar");

      const countColumns = (trackList) => {
        const normalized = (trackList || "").trim();
        return normalized && normalized !== "none" ? normalized.split(/\s+/).length : 0;
      };

      const requestSwitchStyles = window.getComputedStyle(requestSwitch);
      const modeTabsStyles = window.getComputedStyle(modeTabs);
      const requestPanelStyles = window.getComputedStyle(requestPanel);
      const heroResponseStyles = window.getComputedStyle(heroResponse);
      const exchangeGridStyles = window.getComputedStyle(exchangeGrid);
      const modeTabsRect = modeTabs.getBoundingClientRect();
      const topbarRect = topbar.getBoundingClientRect();
      const stageRect = document.querySelector(".workspace-stage").getBoundingClientRect();
      const modeTabButtons = Array.from(
        modeTabs.querySelectorAll(".tab[role=\"tab\"]:not([hidden])")
      );
      const modeTabsFit = modeTabButtons.length > 0 && modeTabButtons.every((button) => {
        const rect = button.getBoundingClientRect();
        return rect.left >= modeTabsRect.left - 1 && rect.right <= modeTabsRect.right + 1;
      });
      const modeTabRects = modeTabButtons.map((button) => button.getBoundingClientRect());

      return {
        viewport: `${window.innerWidth}x${window.innerHeight}`,
        scrollWidth: doc.scrollWidth,
        requestMethodColumns: countColumns(requestSwitchStyles.gridTemplateColumns),
        modeTabsDisplay: modeTabsStyles.display,
        modeTabsColumns: countColumns(modeTabsStyles.gridTemplateColumns),
        modeTabsScrollable: modeTabs.scrollWidth > modeTabs.clientWidth,
        modeTabsFit,
        minModeTabWidth: Math.round(Math.min(...modeTabRects.map((rect) => rect.width))),
        minModeTabHeight: Math.round(Math.min(...modeTabRects.map((rect) => rect.height))),
        exchangeColumns: countColumns(exchangeGridStyles.gridTemplateColumns),
        exchangeScrollWidth: exchangeScroll.scrollWidth,
        exchangeClientWidth: exchangeScroll.clientWidth,
        requestPanelPaddingTop: parseFloat(requestPanelStyles.paddingTop),
        topbarHeight: Math.round(topbarRect.height),
        modeTabsHeight: Math.round(modeTabsRect.height),
        stageTop: Math.round(stageRect.top),
        heroResponseMinHeight: parseFloat(heroResponseStyles.minHeight),
      };
    });

    await page.locator("#tab-upload").click();
    await waitForTabState("upload", { focused: true });
    await waitForPageCondition(
      "mobile upload profile summary fits viewport",
      () => {
        const profile = document.getElementById("uploadProfileGroup")?.getBoundingClientRect();
        const summary = document.getElementById("uploadRequestSummary")?.getBoundingClientRect();
        return Boolean(
          profile &&
          summary &&
          profile.left >= 0 &&
          summary.left >= 0 &&
          profile.right <= innerWidth &&
          summary.right <= innerWidth
        );
      },
      null,
      timeout
    );
    await assertVisibleUploadMethodComposer("mobile upload methods visible with profile summary");

    const filesBrowseGenerationBeforeTabSwitch = await page.evaluate(() => (
      window.XferryApp.getState("files").browseGeneration
    ));
    await page.locator("#tab-files").click();
    await waitForTabState("files", { focused: true });
    await waitForPageCondition(
      "mobile Files automatic browse settles before explicit /uploads browse",
      ([previousGeneration]) => {
        const state = window.XferryApp.getState("files");
        const list = document.getElementById("serverFiles");
        const status = document.getElementById("filesBrowseStatus");
        return Boolean(
          state.browseGeneration > previousGeneration &&
          list?.dataset.browsePhase === "complete" &&
          list.getAttribute("aria-busy") === "false" &&
          status?.dataset.browsePhase === "complete"
        );
      },
      [filesBrowseGenerationBeforeTabSwitch],
      timeout
    );
    await page.locator("#browsePathInput").fill("/uploads");
    await page.getByRole("button", { name: /^(Обзор|Browse)/ }).click();
    await waitForPageCondition(
      "mobile /uploads Files list settles",
      () => {
        const pathInput = document.getElementById("browsePathInput");
        const list = document.getElementById("serverFiles");
        const header = document.getElementById("filesListHeader");
        const headerRect = header?.getBoundingClientRect();
        const visibleRows = Array.from(document.querySelectorAll(".uploaded-file--file"))
          .filter((row) => !row.hidden && row.getClientRects().length > 0);
        return Boolean(
          pathInput?.value === "/uploads" &&
          list?.dataset.browsePhase === "complete" &&
          list.getAttribute("aria-busy") === "false" &&
          visibleRows.length > 0 &&
          header &&
          !header.hidden &&
          header.getClientRects().length > 0 &&
          headerRect &&
          headerRect.width > 0 &&
          headerRect.height > 0
        );
      },
      null,
      timeout
    );
    const mobileFilesHeader = await page.evaluate(() => {
      const header = document.getElementById("filesListHeader");
      const list = document.getElementById("serverFiles");
      const controlTargets = [
        document.getElementById("filesSearchInput"),
        document.querySelector("#filesGlobalActions > summary"),
        document.getElementById("filesSortNameBtn"),
        document.getElementById("filesSelectVisibleCheckbox")?.closest("label"),
      ].filter(Boolean);
      const controls = controlTargets.map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          id: element.id || element.getAttribute("for") || element.className || element.tagName,
          width: rect.width,
          height: rect.height,
        };
      });
      const badRoles = [header, ...Array.from(header?.children || [])]
        .filter(Boolean)
        .map(node => node.getAttribute("role"))
        .filter(Boolean);
      return {
        headerVisible: Boolean(header && !header.hidden && header.getClientRects().length > 0),
        badRoles,
        controls,
        listOverflow: Boolean(list && list.scrollWidth > list.clientWidth + 1),
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      };
    });
    if (
      !mobileFilesHeader.headerVisible ||
      mobileFilesHeader.badRoles.length > 0 ||
      mobileFilesHeader.listOverflow ||
      mobileFilesHeader.documentOverflow ||
      mobileFilesHeader.controls.length !== 4 ||
      mobileFilesHeader.controls.some((control) => control.width < 44 || control.height < 44)
    ) {
      throw new Error(`Mobile Files list header geometry failed: ${JSON.stringify(mobileFilesHeader)}`);
    }
    const mobileDisclosure = page.locator(".uploaded-file--file .file-row__more").first();
    const mobileSecondary = mobileDisclosure.locator(".file-row__actions-secondary");
    const mobileRow = mobileDisclosure.locator("xpath=ancestor::*[contains(@class, 'uploaded-file')][1]");
    const closedRowHeight = await mobileRow.evaluate((row) => row.getBoundingClientRect().height);
    if (await mobileSecondary.isVisible()) {
      throw new Error("Mobile file secondary actions are visible before More is expanded");
    }
    await mobileDisclosure.locator(":scope > summary").click();
    await mobileSecondary.waitFor({ state: "visible", timeout });
    const fileActionLayout = await mobileRow.evaluate((row, beforeHeight) => {
      const rowRect = row.getBoundingClientRect();
      const actions = row.querySelector(".file-row__actions");
      const actionsRect = actions?.getBoundingClientRect();
      const downloadRect = row.querySelector('[data-file-action="download"]')?.getBoundingClientRect();
      const triggerRect = row.querySelector(".file-row__more > summary")?.getBoundingClientRect();
      const secondary = row.querySelector(".file-row__actions-secondary");
      const secondaryRect = secondary?.getBoundingClientRect();
      const actionRects = Array.from(secondary?.querySelectorAll(".btn--sm") || []).map((button) => {
        const rect = button.getBoundingClientRect();
        return {
          action: button.getAttribute("data-file-action") || button.textContent?.trim() || "",
          width: rect.width,
          height: rect.height,
        };
      });
      return {
        beforeHeight,
        afterHeight: rowRect.height,
        secondaryPosition: getComputedStyle(secondary).position,
        panelMatchesActionArea: Boolean(
          secondaryRect && actionsRect &&
          Math.abs(secondaryRect.left - actionsRect.left) <= 1 &&
          Math.abs(secondaryRect.right - actionsRect.right) <= 1 &&
          Math.abs(secondaryRect.width - actionsRect.width) <= 1
        ),
        panelBelowActionRow: Boolean(
          secondaryRect && downloadRect && triggerRect &&
          secondaryRect.top >= Math.max(downloadRect.bottom, triggerRect.bottom) - 1 &&
          Math.abs(downloadRect.top - triggerRect.top) <= 1
        ),
        hasOverflow: row.scrollWidth > row.clientWidth + 2,
        documentOverflow: document.documentElement.scrollWidth > innerWidth + 1,
        actionRects,
      };
    }, closedRowHeight);
    if (
      fileActionLayout.secondaryPosition !== "absolute" ||
      !fileActionLayout.panelMatchesActionArea ||
      !fileActionLayout.panelBelowActionRow ||
      fileActionLayout.hasOverflow ||
      fileActionLayout.documentOverflow ||
      fileActionLayout.actionRects.length === 0 ||
      fileActionLayout.actionRects.some((rect) => rect.width < 44 || rect.height < 44)
    ) {
      throw new Error(`Mobile More overlay geometry failed: ${JSON.stringify(fileActionLayout)}`);
    }
    await page.screenshot({
      path: `${artifactDir}/files-compact-mobile-expanded.png`,
      fullPage: true,
    });

    await page.setViewportSize({ width: 1440, height: 1024 });
    return snapshot;
  }

  async function runFirstRunJourney() {
    const startedAt = Date.now();
    await assertOutputLiveRegionContracts();
    await assertStaticUiAssetsLoaded();
    await assertVisibleAppVersion();
    await waitForAdvancedUploadReady();
    await assertTopTabContract({
      lang: "ru",
      viewportLabel: "first-run desktop",
      expectedActive: "upload",
      verifyFocusOrder: false,
    });

    const uploadName = uploadFilePath.split(/[\\/]/).pop();
    const upload = await uploadViaDom(uploadName);
    await browseUploadsAndAssert(uploadName);
    await waitForLiveRegionText("filesResponseAreaLive", "INFO /uploads 200 OK", 10000);
    await fetchViaServerFilesAndAssert(uploadName);
    await assertDeleteDialogKeyboardContract(uploadName);
    await deleteViaServerFilesAndAssert(uploadName);
    await assertClearUploadsGlobalActionsAndRetryConfirmation();

    const durationMs = Date.now() - startedAt;
    if (durationMs >= 300000) {
      throw new Error(`First-run exceeded five minutes: ${durationMs}ms`);
    }
    return {
      uploadedFile: uploadName,
      uploadedSize: upload.selectedSizeText,
      downloadedFile: uploadName,
      deletedFile: uploadName,
      durationMs,
    };
  }

  async function runBasicUploadProfilesJourney() {
    const task3ReviewerFailures = [];
    const responsiveUpload = await assertResponsiveUploadSummaryAndActions();
    await switchLanguage("en");
    await page.locator("#tab-upload").click();
    await waitForTabState("upload", { focused: true });

    const initialContract = await page.evaluate(() => {
      const buttons = Array.from(
        document.querySelectorAll("#uploadProfileGroup [data-upload-profile]")
      );
      return {
        profiles: buttons.map((button) => button.dataset.uploadProfile),
        checked: buttons.filter((button) => button.getAttribute("aria-checked") === "true")
          .map((button) => button.dataset.uploadProfile),
        tabbable: buttons.filter((button) => button.tabIndex === 0)
          .map((button) => button.dataset.uploadProfile),
        summary: {
          requestLine: document.querySelector('[data-upload-summary="request-line"]')?.textContent,
          bodyKind: document.querySelector('[data-upload-summary="body-kind"]')?.textContent,
          mime: document.querySelector('[data-upload-summary="mime"]')?.textContent,
          filenameSource: document.querySelector('[data-upload-summary="filename-source"]')?.textContent,
        },
      };
    });
    if (
      initialContract.profiles.join(",") !== "multipart,raw-url,raw-header" ||
      initialContract.checked.join(",") !== "multipart" ||
      initialContract.tabbable.join(",") !== "multipart"
    ) {
      throw new Error(`Basic profile radio contract failed: ${JSON.stringify(initialContract)}`);
    }
    const primaryActionGeometry =
      await assertUploadPrimaryActionDoesNotShiftAfterSelection();

    await page.locator('[data-upload-profile="multipart"]').focus();
    await page.keyboard.press("End");
    await waitForPageCondition(
      "profile End key selects raw-header",
      () => (
        document.activeElement?.getAttribute("data-upload-profile") === "raw-header" &&
        document.activeElement?.getAttribute("aria-checked") === "true"
      )
    );
    await page.keyboard.press("Home");
    await waitForPageCondition(
      "profile Home key selects multipart",
      () => (
        document.activeElement?.getAttribute("data-upload-profile") === "multipart" &&
        document.activeElement?.getAttribute("aria-checked") === "true"
      )
    );

    const compiler = await page.evaluate(() => {
      const app = window.XferryApp;
      const bytes = new TextEncoder().encode("abc");
      const file = new File([bytes], "кириллица #1.bin", {
        type: "application/x-profile-test",
      });
      const serialize = (profile) => {
        const plan = app.invoke(
          "upload",
          "compile-request",
          { method: "PATCH", profile },
          file,
          bytes.buffer
        );
        const formFile = plan.body instanceof FormData ? plan.body.get("file") : null;
        return {
          profile: plan.profile,
          method: plan.method,
          pathname: plan.pathname,
          requestUrl: plan.requestUrl,
          wireHeaders: plan.wireHeaders,
          traceHeaders: plan.traceHeaders,
          mime: plan.mime,
          bodyKind: plan.bodyKind,
          filenameSource: plan.filenameSource,
          bodyType: plan.body?.constructor?.name || "",
          formFile: formFile instanceof File
            ? { name: formFile.name, type: formFile.type, size: formFile.size }
            : null,
          requestLine: `${plan.requestExchange.method} ${plan.requestExchange.path}`,
        };
      };
      return ["multipart", "raw-url", "raw-header"].map(serialize);
    });
    const [multipart, rawUrl, rawHeader] = compiler;
    if (
      multipart.pathname !== "/uploads" ||
      multipart.bodyType !== "FormData" ||
      multipart.formFile?.name !== "кириллица #1.bin" ||
      multipart.formFile?.type !== "application/x-profile-test" ||
      Object.keys(multipart.wireHeaders).some((name) => (
        name.toLowerCase() === "content-type" ||
        name.toLowerCase() === "content-length" ||
        name.toLowerCase() === "x-file-name"
      ))
    ) {
      throw new Error(`Multipart compiler wire mismatch: ${JSON.stringify(multipart)}`);
    }
    if (
      rawUrl.pathname !== "/uploads/%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0%20%231.bin" ||
      rawUrl.wireHeaders["Content-Type"] !== "application/x-profile-test" ||
      Object.keys(rawUrl.wireHeaders).some((name) => name.toLowerCase() === "x-file-name") ||
      Object.keys(rawUrl.wireHeaders).some((name) => name.toLowerCase() === "content-length")
    ) {
      throw new Error(`Raw URL compiler wire mismatch: ${JSON.stringify(rawUrl)}`);
    }
    if (
      rawHeader.pathname !== "/uploads" ||
      rawHeader.wireHeaders["Content-Type"] !== "application/octet-stream" ||
      rawHeader.wireHeaders["X-File-Name"] !==
        "%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0%20%231.bin" ||
      Object.keys(rawHeader.wireHeaders)
        .filter((name) => name.toLowerCase() === "x-file-name").length !== 1 ||
      rawHeader.wireHeaders["X-File-Name"].includes("%25")
    ) {
      throw new Error(`Raw Header compiler wire mismatch: ${JSON.stringify(rawHeader)}`);
    }
    const multipartFallbackMime = await page.evaluate(() => {
      const file = new File([new Uint8Array([1])], "untyped.bin");
      const plan = window.XferryApp.invoke(
        "upload",
        "compile-request",
        { method: "POST", profile: "multipart" },
        file
      );
      const part = plan.body.get("file");
      return {
        planMime: plan.mime,
        partMime: part instanceof File ? part.type : "",
      };
    });
    if (
      multipartFallbackMime.planMime !== "application/octet-stream" ||
      multipartFallbackMime.partMime !== "application/octet-stream"
    ) {
      throw new Error(
        `Multipart MIME fallback mismatch: ${JSON.stringify(multipartFallbackMime)}`
      );
    }

    const queuedSend = await page.evaluate(async () => {
      const app = window.XferryApp;
      const http = app.service("http");
      const calls = [];
      let active = 0;
      let maxActive = 0;
      const response = (payload) => ({
        status: 201,
        ok: true,
        statusText: "Created",
        headers: { "content-type": "application/json" },
        rawResponseHeadersText: "content-type: application/json\r\n",
        text: async () => JSON.stringify(payload),
        blob: async () => new Blob([JSON.stringify(payload)]),
      });
      http["set-adapter"](async (method, url, body, headers = {}) => {
        const pathname = new URL(url, location.href).pathname;
        active += 1;
        maxActive = Math.max(maxActive, active);
        const profile = body instanceof FormData
          ? "multipart"
          : (Object.keys(headers).some((name) => name.toLowerCase() === "x-file-name")
            ? "raw-header"
            : "raw-url");
        const formFile = body instanceof FormData ? body.get("file") : null;
        calls.push({
          method,
          pathname,
          profile,
          headers: { ...headers },
          bodyType: body?.constructor?.name || "",
          formName: formFile instanceof File ? formFile.name : "",
        });
        await Promise.resolve();
        active -= 1;
        const name = formFile instanceof File
          ? formFile.name
          : decodeURIComponent(
            headers["X-File-Name"] || pathname.split("/").pop() || "queued.bin"
          );
        return response({
          file: {
            name,
            path: `/uploads/${name}`,
            size_bytes: 1,
            size_human: "1 B",
            content_type: "text/plain",
            uploaded_at: "2026-08-14T00:00:00+00:00",
            sha256: "a".repeat(64),
          },
          upload: {
            kind: "basic",
            profile,
            carrier: profile === "multipart" ? "multipart" : "body",
            filename_source: profile === "multipart" ? "part" : (profile === "raw-header" ? "header" : "url"),
            normalized_name: name,
            collision_renamed: false,
            request_body_size: 1,
            payload_size: 1,
          },
        });
      });

      const scenarios = [
        ["multipart", "POST"],
        ["raw-url", "PUT"],
        ["raw-header", "NONE"],
      ];
      for (const [profile, method] of scenarios) {
        app.invoke("upload", "set-profile", profile);
        app.invoke("upload", "set-method", method);
        const files = [0, 1].map(index => new File(
          [new TextEncoder().encode(`${profile}-${index}`)],
          `${profile}-${index}.txt`,
          { type: "text/plain" }
        ));
        app.invoke("upload", "handle-files", files);
        await app.invoke("upload", "send");
      }
      http["reset-adapter"]();
      return {
        calls,
        maxActive,
        state: app.getState("upload"),
      };
    });
    if (
      queuedSend.calls.length !== 6 ||
      queuedSend.maxActive !== 1 ||
      queuedSend.calls.map((call) => call.profile).join(",") !==
        "multipart,multipart,raw-url,raw-url,raw-header,raw-header" ||
      queuedSend.calls.map((call) => call.method).join(",") !==
        "POST,POST,PUT,PUT,NONE,NONE" ||
      queuedSend.calls.slice(0, 2).some((call) => (
        call.pathname !== "/uploads" ||
        call.bodyType !== "FormData" ||
        Object.keys(call.headers).some((name) => name.toLowerCase() === "content-type")
      )) ||
      queuedSend.calls.slice(2, 4).some((call) => (
        !call.pathname.startsWith("/uploads/raw-url-") ||
        Object.keys(call.headers).some((name) => name.toLowerCase() === "x-file-name")
      )) ||
      queuedSend.calls.slice(4).some((call) => (
        call.pathname !== "/uploads" ||
        call.headers["Content-Type"] !== "application/octet-stream" ||
        Object.keys(call.headers)
          .filter((name) => name.toLowerCase() === "x-file-name").length !== 1
      )) ||
      queuedSend.state.pendingCount !== 0
    ) {
      throw new Error(`Queued send/compiler reuse failed: ${JSON.stringify(queuedSend)}`);
    }

    const coexistenceSetup = await page.evaluate(async () => {
      const app = window.XferryApp;
      const session = app.service("advanced-session");
      await session.ensureActive();
      app.invoke("upload", "set-method", "POST");
      app.invoke("upload", "set-profile", "multipart");
      app.invoke("upload", "handle-files", [
        new File([new TextEncoder().encode("basic")], "basic-coexists.txt", {
          type: "text/plain",
        }),
      ]);
      return {
        sessionActive: session.getSnapshot().active,
        sendDisabled: document.getElementById("uploadBtn")?.disabled,
        compareDisabled: document.getElementById("uploadCompareBtn")?.disabled,
      };
    });
    if (
      coexistenceSetup.sessionActive !== true ||
      coexistenceSetup.sendDisabled !== false ||
      coexistenceSetup.compareDisabled !== false
    ) {
      throw new Error(
        `Basic/Advanced session coexistence setup failed: ${JSON.stringify(coexistenceSetup)}`
      );
    }

    const basicSendResponsePromise = page.waitForResponse((response) => (
      response.request().method() === "POST" &&
      requestPathname(response.request()) === "/uploads"
    ), { timeout: 15000 });
    await page.locator("#uploadBtn").click();
    const basicSendResponse = await basicSendResponsePromise;
    const basicSendPayload = await basicSendResponse.json();
    await waitForPageCondition(
      "real Basic upload completes while Advanced session stays active",
      () => (
        window.XferryApp.service("inspector").getInspectorState("upload")?.response?.phase ===
          "complete" &&
        window.XferryApp.service("advanced-session").getSnapshot().active === true
      ),
      null,
      15000
    );
    const actualBasicSend = {
      status: basicSendResponse.status(),
      kind: basicSendPayload?.upload?.kind || "",
      profile: basicSendPayload?.upload?.profile || "",
      sessionHeaderAbsent: !basicSendResponse.request().headers()[
        "x-xferry-advanced-session"
      ],
      sessionActive: await page.evaluate(() => (
        window.XferryApp.service("advanced-session").getSnapshot().active
      )),
    };

    const compareSetup = await page.evaluate(() => {
      const app = window.XferryApp;
      app.invoke("upload", "set-method", "POST");
      app.invoke("upload", "set-profile", "multipart");
      app.invoke("upload", "handle-files", [
        new File(
          [new TextEncoder().encode("basic compare while advanced is active")],
          "basic-compare-coexists.txt",
          { type: "text/plain" }
        ),
      ]);
      return {
        pendingCount: app.getState("upload").pendingCount,
        sessionActive: app.service("advanced-session").getSnapshot().active,
        compareDisabled: document.getElementById("uploadCompareBtn")?.disabled,
      };
    });
    const compareResponses = [];
    const captureCompareResponse = (response) => {
      const request = response.request();
      if (
        request.method() === "POST" &&
        requestPathname(request).startsWith("/uploads")
      ) {
        compareResponses.push({
          status: response.status(),
          path: requestPathname(request),
          sessionHeaderAbsent: !request.headers()["x-xferry-advanced-session"],
        });
      }
    };
    page.on("response", captureCompareResponse);
    await page.locator("#uploadCompareBtn").click();
    await page.locator('#appDialog [role="alertdialog"]').waitFor({ state: "visible" });
    await page.locator('#appDialog [data-dialog-action="confirm"]').click();
    await waitForPageCondition(
      "real Basic comparison settles while Advanced session stays active",
      () => {
        const app = window.XferryApp;
        const state = app.getState("upload");
        return state.actionPhase === "idle" &&
          state.compareResults.length === 3 &&
          state.compareResults.every((result) => result.verdict !== "not-run") &&
          app.service("advanced-session").getSnapshot().active === true;
      },
      null,
      15000
    );
    page.off("response", captureCompareResponse);
    const actualBasicCompare = await page.evaluate(() => {
      const app = window.XferryApp;
      const snapshot = app.service("advanced-session").getSnapshot();
      const results = app.getState("upload").compareResults;
      const rows = Array.from(document.querySelectorAll("[data-upload-compare-result]"));
      return {
        sessionActive: snapshot.active,
        sessionPhase: snapshot.phase,
        profiles: results.map((result) => result.profile),
        verdicts: results.map((result) => result.verdict),
        domProfiles: rows.map((row) => row.dataset.uploadCompareResult),
        requestTracesPresent: rows.every((row) => Boolean(
          row.querySelector("[data-upload-compare-request]")?.textContent
        )),
        responseTracesPresent: rows.every((row) => Boolean(
          row.querySelector("[data-upload-compare-response]")?.textContent
        )),
      };
    });
    const basicAdvancedCoexistence = {
      ...coexistenceSetup,
      actualBasicSend,
      compareSetup,
      actualBasicCompare,
      compareResponses,
    };
    if (
      actualBasicSend.status !== 201 ||
      actualBasicSend.kind !== "basic" ||
      actualBasicSend.profile !== "multipart" ||
      actualBasicSend.sessionHeaderAbsent !== true ||
      actualBasicSend.sessionActive !== true ||
      compareSetup.pendingCount !== 1 ||
      compareSetup.sessionActive !== true ||
      compareSetup.compareDisabled !== false ||
      compareResponses.length !== 3 ||
      compareResponses.some((response) => (
        response.status !== 201 || response.sessionHeaderAbsent !== true
      )) ||
      actualBasicCompare.sessionActive !== true ||
      actualBasicCompare.sessionPhase !== "active" ||
      actualBasicCompare.profiles.join(",") !== "multipart,raw-url,raw-header" ||
      actualBasicCompare.domProfiles.join(",") !== "multipart,raw-url,raw-header" ||
      actualBasicCompare.verdicts.join(",") !==
        "delivered,metadata-changed,metadata-changed" ||
      actualBasicCompare.requestTracesPresent !== true ||
      actualBasicCompare.responseTracesPresent !== true
    ) {
      throw new Error(
        `Real Basic/Advanced session coexistence failed: ${JSON.stringify(basicAdvancedCoexistence)}`
      );
    }
    await page.evaluate(async () => {
      const app = window.XferryApp;
      await app.service("advanced-session").revoke();
      app.invoke("upload", "handle-files", []);
    });

    await page.screenshot({
      path: `${artifactDir}/basic-upload-profiles-desktop.png`,
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: `${artifactDir}/basic-upload-profiles-mobile.png`,
      fullPage: true,
    });
    const mobile = await page.evaluate(() => {
      const group = document.getElementById("uploadProfileGroup");
      const results = document.getElementById("uploadCompareResults");
      return {
        viewportWidth: innerWidth,
        documentWidth: document.documentElement.scrollWidth,
        groupWidth: group?.getBoundingClientRect().width || 0,
        resultsWidth: results?.getBoundingClientRect().width || 0,
      };
    });
    await page.setViewportSize({ width: 1440, height: 1024 });
    if (
      mobile.documentWidth > mobile.viewportWidth + 1 ||
      mobile.groupWidth > mobile.viewportWidth ||
      mobile.resultsWidth > mobile.viewportWidth
    ) {
      throw new Error(`Basic upload mobile layout overflowed: ${JSON.stringify(mobile)}`);
    }

    return {
      compiler,
      responsiveUpload,
      multipartFallbackMime,
      primaryActionGeometry,
      queuedSend,
      basicAdvancedCoexistence,
      mobile,
      screenshots: [
        "basic-upload-profiles-desktop.png",
        "basic-upload-profiles-mobile.png",
      ],
    };
  }

  async function assertCanonicalConsumerFlowsContract() {
    await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForAdvancedUploadReady();
    await page.locator("#tab-upload").click();
    await waitForTabState("upload", { focused: true });

    const setup = await page.evaluate(async () => {
      const app = window.XferryApp;
      const http = app.service("http");
      const state = {
        phase: "basic-success",
        clearTargets: [],
        items: [
          "contract-detail.txt",
          "contract-malformed-detail.txt",
          "contract-directory-detail.txt",
          "contract-delete.txt",
          "contract-malformed-delete.txt",
          "contract-clear.txt",
        ],
      };
      const response = (status, payload, statusText = "OK") => new Response(
        JSON.stringify(payload),
        { status, statusText, headers: { "Content-Type": "application/json" } }
      );
      const file = (name, contents = "contract") => new File(
        [contents], name, { type: "text/plain" }
      );
      const fileEntry = (name) => ({
        name,
        path: `/uploads/${name}`,
        kind: "file",
        size_bytes: 8,
        size_human: "8 B",
        content_type: "text/plain",
        created_at: "2026-08-14T00:00:00+00:00",
        modified_at: "2026-08-14T00:01:00+00:00",
      });
      const directory = (path) => ({
        entry: { kind: "directory", path },
        page: { total_items: state.items.length + 4 },
        contents: state.items.map((name) => ({ name, kind: "file" })),
      });
      const sessionIssuedAt = Date.now();
      const sessionMetadata = {
        prefix: "/advanced",
        decoder: "auto",
        diagnostic_headers: true,
        created_at: new Date(sessionIssuedAt).toISOString(),
        expires_at: new Date(sessionIssuedAt + 60 * 60 * 1000).toISOString(),
        idle_timeout_seconds: 900,
      };
      const originalAdapter = http["set-adapter"](async (method, url) => {
        const requestUrl = new URL(String(url), location.href);
        const { pathname, search } = requestUrl;
        if (
          pathname === "/_xferry/advanced-sessions" ||
          pathname === "/_xferry/advanced-sessions/current"
        ) {
          return response(method === "POST" ? 201 : 200, {
            advanced_session: method === "POST"
              ? { token: "S".repeat(43), ...sessionMetadata }
              : sessionMetadata,
          });
        }
        if (method === "INFO") {
          if (pathname === "/uploads/contract-detail.txt") {
            return response(200, { entry: fileEntry("contract-detail.txt") });
          }
          if (pathname === "/uploads/contract-malformed-detail.txt") {
            return response(200, {
              entry: {
                kind: "file",
                path: pathname,
                name: "contract-malformed-detail.txt",
                size_bytes: 8,
                created_at: "2026-08-14T00:00:00+00:00",
              },
            });
          }
          if (pathname === "/uploads/contract-directory-detail.txt") {
            return response(200, directory(pathname));
          }
          return response(200, directory(pathname));
        }
        if (method === "DELETE" && pathname === "/uploads") {
          state.clearTargets.push(search);
          if (search !== "?clear=true") {
            throw new Error(`Files clear request target is not strict: ${pathname}${search}`);
          }
          if (state.phase === "clear-malformed") {
            return response(200, { cleared_uploads: { path: "/uploads" } });
          }
          const deletedFiles = state.items.length;
          state.items = [];
          return response(200, {
            cleared_uploads: {
              path: "/uploads",
              deleted_files: deletedFiles,
              deleted_dirs: 0,
            },
          });
        }
        if (method === "DELETE") {
          const name = decodeURIComponent(pathname.split("/").pop() || "");
          if (name === "contract-malformed-delete.txt") {
            return response(200, { deleted_file: {} });
          }
          state.items = state.items.filter((item) => item !== name);
          return response(200, { deleted_file: { name, path: pathname } });
        }
        if (state.phase === "basic-success") {
          return response(201, {
            file: {
              name: "contract-basic.txt",
              path: "/uploads/basic-final-server.txt",
              size_bytes: 8,
              size_human: "8 B",
              content_type: "text/plain",
              uploaded_at: "2026-08-14T00:00:00+00:00",
              sha256: "a".repeat(64),
            },
            upload: {
              kind: "basic",
              profile: "raw-url",
              carrier: "body",
              filename_source: "url",
              normalized_name: "contract-basic.txt",
              collision_renamed: false,
              request_body_size: 8,
              payload_size: 8,
            },
          }, "Created");
        }
        if (state.phase === "basic-error") {
          return response(403, {
            error: {
              code: "basic_contract_denied",
              message: "Basic nested contract error",
              field: null,
              details: {},
            },
          }, "Forbidden");
        }
        if (state.phase === "advanced-success") {
          return response(200, {
            file: {
              name: "contract-advanced.txt",
              path: "/uploads/advanced-final-server.txt",
            },
            upload: { kind: "advanced" },
          });
        }
        return response(403, {
          error: {
            code: "advanced_contract_denied",
            message: "Advanced nested contract error",
            field: null,
            details: {},
          },
        }, "Forbidden");
      });
      window.__canonicalConsumerContract = { http, originalAdapter, state };

      app.invoke("upload", "set-method", "POST");
      app.invoke("upload", "set-profile", "raw-url");
      app.invoke("upload", "handle-files", [file("contract-basic.txt")]);
      await app.invoke("upload", "send");
      const basicSuccess = {
        phase: app.service("inspector").getInspectorState("upload")?.response?.phase || "",
        summary: app.service("inspector").getInspectorState("upload")?.response?.summaryText || "",
        serverPath: document.querySelector(
          '[data-upload-result-field="server-path"] .tool-result__meta-value'
        )?.textContent || "",
      };

      state.phase = "basic-error";
      app.invoke("upload", "handle-files", [file("contract-basic-error.txt")]);
      await app.invoke("upload", "send");
      const basicError = {
        phase: app.service("inspector").getInspectorState("upload")?.response?.phase || "",
        summary: app.service("inspector").getInspectorState("upload")?.response?.summaryText || "",
        card: document.querySelector("#uploadHttpErrorHost .http-error-card")?.textContent || "",
      };
      app.service("http-errors").close("uploadHttpErrorHost", { restore: false });

      state.phase = "advanced-success";
      await app.service("advanced-session").ensureActive();
      await app.service("advanced-session").current();
      app.invoke("advanced", "set-file", file("contract-advanced.txt"));
      await app.invoke("advanced", "refresh-preview");
      await app.invoke("advanced", "send");
      const advancedSuccess = {
        phase: app.service("inspector").getInspectorState("opsec")?.response?.phase || "",
        summary: app.service("inspector").getInspectorState("opsec")?.response?.summaryText || "",
      };

      state.phase = "advanced-error";
      app.invoke("advanced", "set-file", file("contract-advanced-error.txt"));
      await app.invoke("advanced", "refresh-preview");
      await app.invoke("advanced", "send");
      const advancedError = {
        phase: app.service("inspector").getInspectorState("opsec")?.response?.phase || "",
        summary: app.service("inspector").getInspectorState("opsec")?.response?.summaryText || "",
        card: document.querySelector("#opsecHttpErrorHost .http-error-card")?.textContent || "",
      };
      app.service("http-errors").close("opsecHttpErrorHost", { restore: false });

      document.getElementById("browsePathInput").value = "/uploads";
      await app.invoke("files", "browse");
      return {
        basicSuccess,
        basicError,
        advancedSuccess,
        advancedError,
        browse: {
          names: Array.from(document.querySelectorAll("#serverFiles .file-name"))
            .map((node) => node.textContent),
          summary: document.getElementById("filesBrowseStatus")?.textContent || "",
        },
      };
    });

    try {
      if (
        setup.basicSuccess.phase !== "complete" ||
        !setup.basicSuccess.summary.includes("/uploads/basic-final-server.txt") ||
        setup.basicSuccess.serverPath !== "/uploads/basic-final-server.txt" ||
        setup.basicError.phase !== "error" ||
        !setup.basicError.card.includes("Basic nested contract error") ||
        setup.advancedSuccess.phase !== "complete" ||
        !setup.advancedSuccess.summary.includes("/uploads/advanced-final-server.txt") ||
        setup.advancedError.phase !== "error" ||
        !setup.advancedError.card.includes("Advanced nested contract error") ||
        setup.browse.names.length !== 6 ||
        !setup.browse.names.includes("contract-detail.txt") ||
        !setup.browse.summary.includes("6") ||
        !setup.browse.summary.includes("10")
      ) {
        throw new Error(`Canonical upload/INFO consumer flow failed: ${JSON.stringify(setup)}`);
      }

      await page.locator("#tab-files").click();
      await waitForTabState("files", { focused: true });
      await page.waitForTimeout(150);
      await page.evaluate(async () => {
        document.getElementById("browsePathInput").value = "/uploads";
        await window.XferryApp.invoke("files", "browse");
      });
      await waitForPageCondition(
        "canonical INFO browse is settled after opening Files",
        () => document.querySelectorAll("#serverFiles .file-name").length === 6,
        null,
        10000
      );
      const detailPath = encodeURIComponent("/uploads/contract-detail.txt");
      await page.locator(`[data-file-details-trigger][data-path="${detailPath}"]`).click();
      const hasCanonicalDetailFields = () => {
        const fields = Object.fromEntries(Array.from(
          document.querySelectorAll(".file-row__details-field")
        ).map((field) => [
          field.dataset.field,
          field.querySelector("dd")?.textContent?.trim() || "",
        ]));
        return fields["file-name"] === "contract-detail.txt" &&
          fields.size === "8 B" &&
          fields.created === "2026-08-14T00:00:00+00:00" &&
          fields.modified === "2026-08-14T00:01:00+00:00";
      };
      try {
        await waitForPageCondition(
          "canonical INFO file metadata renders",
          hasCanonicalDetailFields,
          null,
          10000
        );
      } catch (error) {
        const diagnostic = await page.evaluate(() => ({
          phase: window.XferryApp.service("inspector").getInspectorState("files")?.response?.phase || "",
          summary: window.XferryApp.service("inspector").getInspectorState("files")?.response?.summaryText || "",
          fields: Object.fromEntries(Array.from(
            document.querySelectorAll(".file-row__details-field")
          ).map((field) => [
            field.dataset.field,
            field.querySelector("dd")?.textContent?.trim() || "",
          ])),
        }));
        throw new Error(`Canonical INFO metadata diagnostic: ${JSON.stringify(diagnostic)}; ${error.message}`);
      }

      const malformedDetailPath = encodeURIComponent("/uploads/contract-malformed-detail.txt");
      await page.locator(`[data-file-details-trigger][data-path="${malformedDetailPath}"]`).click();
      await waitForPageCondition(
        "malformed INFO 2xx is rejected",
        ([path]) => {
          const trigger = document.querySelector(
            `[data-file-details-trigger][data-path="${path}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          return trigger?.getAttribute("aria-expanded") === "true" && !panel?.hidden &&
            Boolean(panel?.querySelector(".file-row__details-status--error")) &&
            panel?.querySelectorAll(".file-row__details-field").length === 0;
        },
        [malformedDetailPath],
        10000
      );
      const malformedInfo = await page.evaluate(() => ({
        fields: document.querySelectorAll(".file-row__details-field").length,
        error: document.querySelector(".file-row__details-status--error")?.textContent || "",
      }));
      if (!malformedInfo.error || malformedInfo.fields !== 0) {
        throw new Error(`Malformed INFO 2xx was accepted: ${JSON.stringify(malformedInfo)}`);
      }

      const directoryDetailPath = encodeURIComponent("/uploads/contract-directory-detail.txt");
      await page.locator(`[data-file-details-trigger][data-path="${directoryDetailPath}"]`).click();
      await waitForPageCondition(
        "directory-shaped INFO detail 2xx is rejected",
        ([path]) => {
          const trigger = document.querySelector(
            `[data-file-details-trigger][data-path="${path}"]`
          );
          const panel = trigger?.getAttribute("aria-controls")
            ? document.getElementById(trigger.getAttribute("aria-controls"))
            : null;
          return trigger?.getAttribute("aria-expanded") === "true" && !panel?.hidden &&
            Boolean(panel?.querySelector(".file-row__details-status--error")) &&
            panel?.querySelectorAll(".file-row__details-field").length === 0;
        },
        [directoryDetailPath],
        10000
      );
      const directoryDetailInfo = await page.evaluate(() => ({
        fields: document.querySelectorAll(".file-row__details-field").length,
        error: document.querySelector(".file-row__details-status--error")?.textContent || "",
      }));
      if (!directoryDetailInfo.error || directoryDetailInfo.fields !== 0) {
        throw new Error(
          `Directory-shaped INFO detail 2xx was accepted: ${JSON.stringify(directoryDetailInfo)}`
        );
      }

      const malformedDeletePath = encodeURIComponent("/uploads/contract-malformed-delete.txt");
      const malformedDeleteButton = await getServerFileAction(
        "contract-malformed-delete.txt", "delete"
      );
      await malformedDeleteButton.click();
      await confirmAppDialog("contract-malformed-delete.txt");
      await waitForPageCondition(
        "malformed DELETE 2xx is rejected",
        ([path]) => {
          const response = window.XferryApp.service("inspector").getInspectorState("files")?.response;
          return response?.phase === "error" && response?.status === 200 &&
            Boolean(document.querySelector(`[data-file-action="delete"][data-path="${path}"]`)) &&
            Boolean(document.querySelector('#appDialog [role="dialog"]'));
        },
        [malformedDeletePath],
        10000
      );
      const malformedDeleteNotice = page.locator('#appDialog [role="dialog"]');
      await malformedDeleteNotice.locator('[data-dialog-action="confirm"]').click();
      await malformedDeleteNotice.waitFor({ state: "detached", timeout: 10000 });

      const deletePath = encodeURIComponent("/uploads/contract-delete.txt");
      const deleteButton = await getServerFileAction("contract-delete.txt", "delete");
      await deleteButton.click();
      await confirmAppDialog("contract-delete.txt");
      await waitForPageCondition(
        "canonical DELETE renders success and refreshes",
        ([path]) => {
          const response = window.XferryApp.service("inspector").getInspectorState("files")?.response;
          return response?.phase === "complete" &&
            response.summaryText.includes("/uploads/contract-delete.txt") &&
            !document.querySelector(`[data-file-action="delete"][data-path="${path}"]`);
        },
        [deletePath],
        10000
      );

      await page.evaluate(() => { window.__canonicalConsumerContract.state.phase = "clear-malformed"; });
      await page.locator("#filesGlobalActions > summary").click();
      await page.locator("#clearUploadsBtn").click();
      await confirmAppDialog(/uploads\//, 10000);
      await waitForPageCondition(
        "malformed clear 2xx is rejected",
        () => window.XferryApp.service("inspector").getInspectorState("files")?.response?.phase === "error",
        null,
        10000
      );
      const malformedClear = await page.evaluate(() => ({
        phase: window.XferryApp.service("inspector").getInspectorState("files")?.response?.phase || "",
        status: window.XferryApp.service("inspector").getInspectorState("files")?.response?.status || 0,
        summary: window.XferryApp.service("inspector").getInspectorState("files")?.response?.summaryText || "",
        itemCount: document.querySelectorAll("#serverFiles .file-name").length,
      }));
      if (
        malformedClear.phase !== "error" ||
        malformedClear.status !== 200 ||
        malformedClear.itemCount !== 5
      ) {
        throw new Error(`Malformed clear 2xx was accepted: ${JSON.stringify(malformedClear)}`);
      }
      await page.locator("#filesHttpErrorHost [data-http-error-action='close']").click();

      await page.evaluate(() => { window.__canonicalConsumerContract.state.phase = "clear-success"; });
      await page.locator("#filesGlobalActions > summary").click();
      await page.locator("#clearUploadsBtn").click();
      await confirmAppDialog(/uploads\//, 10000);
      await waitForPageCondition(
        "canonical clear renders success and refreshes",
        () => {
          const response = window.XferryApp.service("inspector").getInspectorState("files")?.response;
          return response?.phase === "complete" && response.summaryText.includes("5") &&
            document.querySelectorAll("#serverFiles .file-name").length === 0;
        },
        null,
        10000
      );
      const clearTargets = await page.evaluate(() => (
        window.__canonicalConsumerContract.state.clearTargets.slice()
      ));
      if (
        clearTargets.length !== 2 ||
        clearTargets.some((target) => target !== "?clear=true")
      ) {
        throw new Error(`Files clear request targets were not strict: ${JSON.stringify(clearTargets)}`);
      }
      return {
        ...setup,
        malformedInfo,
        directoryDetailInfo,
        malformedClear,
        clearSummary: await page.evaluate(() => (
          window.XferryApp.service("inspector").getInspectorState("files")?.response?.summaryText || ""
        )),
        clearTargets,
      };
    } finally {
      await page.evaluate(() => {
        const contract = window.__canonicalConsumerContract;
        if (contract) {
          contract.http["set-adapter"](contract.originalAdapter);
          delete window.__canonicalConsumerContract;
        }
      });
    }
  }

  async function runUiContractsJourney() {
    await assertOutputLiveRegionContracts();
    await assertStaticUiAssetsLoaded();
    await assertApplicationModuleContract();
    const filesCompactExplorer = await assertFilesCompactExplorerContract();
    const filesDeleteTargets = await assertFilesDeleteTargetEncodingContract();
    const filesInfoLastResultWins = await assertFilesInfoLastResultWinsContract();
    await assertSafeUserDataListRendering();
    await assertFilesStaleBrowseGuard();
    await assertVisibleAppVersion();
    await waitForAdvancedUploadReady();
    await assertTopTabContract({
      lang: "ru",
      viewportLabel: "ui-contracts desktop",
      expectedActive: "upload",
    });
    await assertDirectHashTabRoutes();
    await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForAdvancedUploadReady();
    await assertUnsupportedStoredLanguageFallsBack();
    await waitForAdvancedUploadReady();
    const headerStateControls = await assertHeaderStateControls();
    const sharedVisualSystem = await assertSharedVisualSystem();
    const headerBrand = await assertHeaderBrandContract();
    const headerActions = await assertHeaderActionsContract();
    await assertTopTabContract({
      lang: "en",
      viewportLabel: "ui-contracts locale",
      expectedActive: "upload",
      verifyFocusOrder: false,
    });
    await assertTopTabContract({
      lang: "ru",
      viewportLabel: "ui-contracts restored locale",
      expectedActive: "upload",
      verifyFocusOrder: false,
    });
    await assertRequestPreviewStorageContract();
    await assertHomeToolEntryState(["upload", "files", "request", "opsec", "notepad"]);
    await assertHeroResponsePanelState("idle");
    const multipleFileSelection = await assertMultipleFileSelectionSummary();
    const visualReviewScreenshots = await captureSharedVisualReview();
    const reducedMotion = await assertReducedMotionAndTextlessDisclosures();
    await assertSharedDialogRoleContract();
    const advancedSession = await assertAdvancedSessionControlContract();
    const canonicalConsumerFlows = await assertCanonicalConsumerFlowsContract();
    return {
      tabs: topTabContract.map((tab) => tab.target),
      locales: ["ru", "en"],
      liveRegions: true,
      dialogs: true,
      headerStateControls,
      headerBrand,
      headerActions,
      sharedVisualSystem,
      canonicalConsumerFlows,
      multipleFileSelection,
      filesCompactExplorer,
      filesDeleteTargets,
      filesInfoLastResultWins,
      reducedMotion,
      advancedSession,
      visualReviewScreenshots,
    };
  }

  async function runRequestMatrixJourney() {
    await page.locator("#tab-request").click();
    await waitForTabState("request", { focused: true });
    const fetchPath = await fetchViaRequestPanelAndAssert();
    return {
      methods: 13,
      fetchPath,
      summaryAndRaw: true,
      batchRerunAndExport: true,
    };
  }

  async function runHttpErrorsJourney() {
    await page.locator("#tab-request").click();
    await waitForTabState("request", { focused: true });
    await switchLanguage("en");
    await page.locator("#themeBtn").focus();
    const hostileResult = await page.evaluate(() => {
      window.__xferryHttpErrorRetryCount = 0;
      window.__xferryHostileHtmlExecuted = false;
      const service = window.XferryApp.service("http-errors");
      return service.show({
        host: "requestHttpErrorHost",
        origin: document.getElementById("themeBtn"),
        retry: () => {
          window.__xferryHttpErrorRetryCount += 1;
        },
        method: "POST",
        path: "/unsafe?token=top-secret",
        status: 422,
        statusText: "Invalid\u0000 payload",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer never-show",
          "x-request-id": "req-42",
        },
        body: JSON.stringify({
          token: "never-show",
          message: '<img src=x onerror="window.__xferryHostileHtmlExecuted=true">',
          nested: { password: "hidden" },
        }),
      }).model;
    });

    if ("rawText" in hostileResult || hostileResult.totalBytes !== 129) {
      throw new Error(`HTTP error model retained an unsafe body shape: ${JSON.stringify(hostileResult)}`);
    }
    await waitForPageCondition(
      "HTTP error card focus and nonmodal contract",
      () => {
        const card = document.querySelector("#requestHttpErrorHost .http-error-card");
        return Boolean(
          card &&
          card.getAttribute("role") === "alert" &&
          card.getAttribute("tabindex") === "-1" &&
          !card.hasAttribute("aria-modal") &&
          document.activeElement === card
        );
      }
    );
    const card = page.locator("#requestHttpErrorHost .http-error-card");
    if ((await card.locator("img").count()) !== 0) {
      throw new Error("Hostile HTTP error HTML became a DOM element");
    }
    const cardText = (await card.textContent()) || "";
    const hostileHtmlExecuted = await page.evaluate(() => Boolean(window.__xferryHostileHtmlExecuted));
    if (
      !cardText.toLowerCase().includes("[redacted]") ||
      cardText.includes("never-show") ||
      cardText.includes("\u0000") ||
      !cardText.includes("<img src=x") ||
      hostileHtmlExecuted
    ) {
      throw new Error(`HTTP error card did not safely redact/render hostile data: ${cardText}`);
    }

    await card.locator('[data-http-error-action="details"]').click();
    const details = card.locator('[data-http-error-details]');
    await details.waitFor({ state: "visible" });
    const detailsText = (await details.textContent()) || "";
    if (!detailsText.includes('"message":') || !detailsText.toLowerCase().includes("[redacted]")) {
      throw new Error(`HTTP error JSON details were not structured/redacted: ${detailsText}`);
    }
    await card.locator('[data-http-error-action="copy"]').click();
    const copied = await page.evaluate(() => window.__xferryBrowserClipboardText);
    if (!copied.toLowerCase().includes("[redacted]") || copied.includes("never-show")) {
      throw new Error(`HTTP error copy output leaked data: ${copied}`);
    }
    await card.locator('[data-http-error-action="retry"]').click();
    const retryCount = await page.evaluate(() => window.__xferryHttpErrorRetryCount);
    if (retryCount !== 1) {
      throw new Error(`HTTP error Retry did not invoke the supplied callback: ${retryCount}`);
    }
    await page.keyboard.press("Escape");
    await card.waitFor({ state: "detached" });
    await waitForPageCondition(
      "HTTP error Escape focus restore",
      () => document.activeElement?.id === "themeBtn"
    );

    await page.locator("#tab-files").click();
    await waitForTabState("files", { focused: true });
    await page.locator("#themeBtn").focus();
    const truncation = await page.evaluate(() => {
      const service = window.XferryApp.service("http-errors");
      return service.show({
        host: "filesHttpErrorHost",
        origin: document.getElementById("themeBtn"),
        method: "FETCH",
        path: "/large-error",
        status: 500,
        statusText: "Server error",
        headers: { "content-type": "text/plain" },
        body: "X".repeat(20 * 1024),
      }).model;
    });
    if (
      truncation.totalBytes !== 20 * 1024 ||
      truncation.capturedBytes !== 16 * 1024 ||
      truncation.shownBytes !== 4 * 1024 ||
      !truncation.truncated ||
      truncation.displayText.length !== 4 * 1024
    ) {
      throw new Error(`HTTP error bounds contract failed: ${JSON.stringify(truncation)}`);
    }
    const filesCard = page.locator("#filesHttpErrorHost .http-error-card");
    await filesCard.locator('[data-http-error-action="close"]').click();
    await filesCard.waitFor({ state: "detached" });
    await waitForPageCondition(
      "HTTP error Close focus restore",
      () => document.activeElement?.id === "themeBtn"
    );

    const largeJsonRedaction = await page.evaluate(() => {
      const service = window.XferryApp.service("http-errors");
      const prefix = JSON.stringify({
        token: "leaked-secret",
        nested: { password: "leaked-password" },
        filler: "",
      });
      const body = JSON.stringify({
        token: "leaked-secret",
        nested: { password: "leaked-password" },
        filler: "X".repeat(20 * 1024 - prefix.length),
      });
      return service.show({
        host: "filesHttpErrorHost",
        origin: document.getElementById("themeBtn"),
        method: "FETCH",
        path: "/large-json-error",
        status: 500,
        statusText: "Server error",
        headers: { "content-type": "application/json" },
        body,
      }).model;
    });
    if (
      largeJsonRedaction.totalBytes !== 20 * 1024 ||
      largeJsonRedaction.capturedBytes !== 16 * 1024 ||
      largeJsonRedaction.shownBytes !== 4 * 1024 ||
      largeJsonRedaction.capturedText.includes("leaked-secret") ||
      largeJsonRedaction.capturedText.includes("leaked-password") ||
      largeJsonRedaction.displayText.includes("leaked-secret") ||
      largeJsonRedaction.displayText.includes("leaked-password")
    ) {
      throw new Error(`Large JSON error redaction/bounds contract failed: ${JSON.stringify(largeJsonRedaction)}`);
    }
    const largeJsonCard = page.locator("#filesHttpErrorHost .http-error-card");
    await largeJsonCard.locator('[data-http-error-action="details"]').click();
    await largeJsonCard.locator('[data-http-error-action="copy"]').click();
    const largeJsonCopy = await page.evaluate(() => window.__xferryBrowserClipboardText);
    const largeJsonCardText = (await largeJsonCard.textContent()) || "";
    if (
      largeJsonCardText.includes("leaked-secret") ||
      largeJsonCardText.includes("leaked-password") ||
      largeJsonCopy.includes("leaked-secret") ||
      largeJsonCopy.includes("leaked-password")
    ) {
      throw new Error(`Large JSON error card/copy leaked a secret: ${JSON.stringify({ largeJsonCardText, largeJsonCopy })}`);
    }
    await largeJsonCard.locator('[data-http-error-action="close"]').click();
    await largeJsonCard.waitFor({ state: "detached" });

    const partialJsonSecretValues = [
      "123456789",
      "false",
      "null",
      "object-secret",
      "escaped",
      "array-secret",
      "incomplete-secret",
    ];
    const partialJsonRedaction = await page.evaluate(() => {
      const service = window.XferryApp.service("http-errors");
      const prefix = '{"token":123456789,"password":false,"cookie":null,"data":{"nested":"object-secret\\"escaped"},"authorization":["array-secret",{"nested":"array-object-secret"}],"client_public_key":{"nested":"incomplete-secret","tail":"';
      const body = prefix + "X".repeat(16 * 1024 - prefix.length);
      return service.show({
        host: "filesHttpErrorHost",
        origin: document.getElementById("themeBtn"),
        method: "FETCH",
        path: "/partial-json-error",
        status: 500,
        statusText: "Server error",
        headers: { "content-type": "application/json" },
        body,
        totalBytes: 20 * 1024,
        bodyTruncated: true,
      }).model;
    });
    const partialJsonCard = page.locator("#filesHttpErrorHost .http-error-card");
    await partialJsonCard.locator('[data-http-error-action="details"]').click();
    await partialJsonCard.locator('[data-http-error-action="copy"]').click();
    const partialJsonCardText = (await partialJsonCard.textContent()) || "";
    const partialJsonCopy = await page.evaluate(() => window.__xferryBrowserClipboardText);
    const partialJsonSurfaces = [
      partialJsonRedaction.capturedText,
      partialJsonRedaction.displayText,
      partialJsonCardText,
      partialJsonCopy,
    ];
    const leakedPartialJsonValue = partialJsonSecretValues.find(secret =>
      partialJsonSurfaces.some(surface => surface.includes(secret))
    );
    if (leakedPartialJsonValue) {
      throw new Error(`Truncated partial JSON error leaked ${leakedPartialJsonValue}: ${JSON.stringify(partialJsonRedaction)}`);
    }
    await partialJsonCard.locator('[data-http-error-action="close"]').click();
    await partialJsonCard.waitFor({ state: "detached" });

    await page.locator("#tab-request").click();
    await waitForTabState("request", { focused: true });
    await openRequestTechnicalDetails();
    await page.evaluate(() => {
      const http = window.XferryApp.service("http");
      window.__xferryHttpErrorDeferredResponses = [];
      window.__xferryHttpErrorOriginalAdapter = http["set-adapter"](() => new Promise(resolve => {
        window.__xferryHttpErrorDeferredResponses.push(resolve);
      }));
      document.getElementById("pathInput").value = "/panel-error?token=panel-secret";
    });
    const requestTrigger = page.locator('button[data-request-method="GET"]');
    await requestTrigger.click();
    await page.locator("#themeBtn").focus();
    await page.evaluate(() => {
      window.__xferryHttpErrorDeferredResponses.shift()({
        status: 503,
        ok: false,
        statusText: "Service unavailable",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer panel-secret",
        },
        text: async () => JSON.stringify({ token: "panel-secret", message: "panel failure" }),
      });
    });
    const panelCard = page.locator("#requestHttpErrorHost .http-error-card");
    await panelCard.waitFor({ state: "visible" });
    const panelCardText = (await panelCard.textContent()) || "";
    if (
      panelCardText.includes("panel-secret") ||
      !panelCardText.toLowerCase().includes("[redacted]")
    ) {
      throw new Error(`Generic request HTTP error did not use the shared redacted card: ${panelCardText}`);
    }
    await panelCard.locator('[data-http-error-action="close"]').click();
    await panelCard.waitFor({ state: "detached" });
    await waitForPageCondition(
      "Request HTTP error Close focus restores the original trigger",
      () => document.activeElement?.dataset.requestMethod === "GET"
    );

    await requestTrigger.click();
    await page.locator("#themeBtn").focus();
    await page.evaluate(() => {
      window.__xferryHttpErrorDeferredResponses.shift()({
        status: 503,
        ok: false,
        statusText: "Service unavailable",
        headers: { "content-type": "text/plain" },
        text: async () => "retry failure",
      });
    });
    await panelCard.waitFor({ state: "visible" });
    await panelCard.locator('[data-http-error-action="retry"]').click();
    await waitForPageCondition(
      "Request HTTP error Retry starts another request",
      () => window.__xferryHttpErrorDeferredResponses.length === 1
    );
    await page.locator("#themeBtn").focus();
    await page.evaluate(() => {
      window.__xferryHttpErrorDeferredResponses.shift()({
        status: 503,
        ok: false,
        statusText: "Service unavailable",
        headers: { "content-type": "text/plain" },
        text: async () => "retry failure",
      });
    });
    await panelCard.waitFor({ state: "visible" });
    await page.keyboard.press("Escape");
    await panelCard.waitFor({ state: "detached" });
    await waitForPageCondition(
      "Request HTTP error Retry/Escape keeps the original trigger",
      () => document.activeElement?.dataset.requestMethod === "GET"
    );

    await page.evaluate(() => {
      const http = window.XferryApp.service("http");
      http["set-adapter"](window.__xferryHttpErrorOriginalAdapter);
      window.__xferryHttpErrorNetworkDeferred = null;
      window.__xferryHttpErrorNetworkAttempts = 0;
      window.__xferryHttpErrorOriginalAdapter = http["set-adapter"](() => new Promise((resolve, reject) => {
        window.__xferryHttpErrorNetworkAttempts += 1;
        window.__xferryHttpErrorNetworkDeferred = { resolve, reject };
      }));
    });
    await requestTrigger.click();
    await page.locator("#themeBtn").focus();
    await page.evaluate(() => {
      window.__xferryHttpErrorNetworkDeferred.reject(new Error("network token=network-secret"));
    });
    await panelCard.waitFor({ state: "visible" });
    const networkCardText = (await panelCard.textContent()) || "";
    if (!networkCardText.includes("0") || networkCardText.includes("network-secret")) {
      throw new Error(`Request network error did not use a bounded redacted HTTP error card: ${networkCardText}`);
    }
    await panelCard.locator('[data-http-error-action="retry"]').click();
    await waitForPageCondition(
      "Request network error Retry starts another request",
      () => window.__xferryHttpErrorNetworkAttempts === 2
    );
    await page.locator("#themeBtn").focus();
    await page.evaluate(() => {
      window.__xferryHttpErrorNetworkDeferred.reject(new Error("network token=network-secret"));
    });
    await panelCard.waitFor({ state: "visible" });
    await page.keyboard.press("Escape");
    await panelCard.waitFor({ state: "detached" });
    await waitForPageCondition(
      "Request network error Escape focus restores the original trigger",
      () => document.activeElement?.dataset.requestMethod === "GET"
    );
    await page.evaluate(() => {
      window.XferryApp.service("http")["set-adapter"](window.__xferryHttpErrorOriginalAdapter);
      delete window.__xferryHttpErrorOriginalAdapter;
      delete window.__xferryHttpErrorDeferredResponses;
      delete window.__xferryHttpErrorNetworkDeferred;
      delete window.__xferryHttpErrorNetworkAttempts;
    });

    await page.locator("#tab-files").click();
    await waitForTabState("files", { focused: true });
    await page.evaluate(() => {
      window.__xferryHttpErrorOriginalXhr = window.XMLHttpRequest;
      window.__xferryFetchTimeout = 0;
      window.__xferryFetchRequestCount = 0;
      window.XMLHttpRequest = class HttpErrorDownloadXhr {
        constructor() {
          this.status = 502;
          this.statusText = "Bad gateway";
          this.response = null;
          this.responseType = "";
          this.timeout = 0;
        }
        open(method, url) {
          this.method = method;
          this.url = url;
        }
        getAllResponseHeaders() {
          return "Content-Type: application/json\r\nAuthorization: Bearer fetch-secret\r\nX-Request-ID: fetch-42\r\n";
        }
        getResponseHeader() {
          return null;
        }
        send() {
          window.__xferryFetchRequestCount += 1;
          window.__xferryFetchTimeout = this.timeout;
          const prefix = JSON.stringify({
            token: "fetch-token-secret",
            nested: { password: "fetch-password-secret" },
            filler: "",
          });
          this.response = new Blob([JSON.stringify({
            token: "fetch-token-secret",
            nested: { password: "fetch-password-secret" },
            filler: "X".repeat(20 * 1024 - prefix.length),
          })], { type: "application/json" });
          queueMicrotask(() => this.onload());
        }
      };
      window.__xferryFetchHtmlExecuted = false;
      document.getElementById("themeBtn").focus();
      void window.XferryApp.invoke("requests", "download-file", "/fetch-http-error");
      document.getElementById("tab-request").focus();
    });
    const fetchCard = page.locator("#filesHttpErrorHost .http-error-card");
    await fetchCard.waitFor({ state: "visible" });
    const fetchIntegration = await page.evaluate(() => ({
      timeout: window.__xferryFetchTimeout,
      hostileHtmlExecuted: window.__xferryFetchHtmlExecuted,
      overlayVisible: Boolean(
        document.getElementById("downloadProgressArea") &&
        !document.getElementById("downloadProgressArea").hidden
      ),
    }));
    const fetchCardText = (await fetchCard.textContent()) || "";
    if (
      fetchIntegration.timeout !== 30000 ||
      fetchIntegration.hostileHtmlExecuted ||
      fetchIntegration.overlayVisible ||
      fetchCardText.includes("fetch-secret") ||
      !fetchCardText.includes("fetch-42")
    ) {
      throw new Error(`FETCH download error contract failed: ${JSON.stringify({ fetchIntegration, fetchCardText })}`);
    }
    await fetchCard.locator('[data-http-error-action="details"]').click();
    await fetchCard.locator('[data-http-error-action="copy"]').click();
    const fetchDetailsText = (await fetchCard.locator('[data-http-error-details]').textContent()) || "";
    const fetchCopy = await page.evaluate(() => window.__xferryBrowserClipboardText);
    if (
      fetchDetailsText.includes("fetch-token-secret") ||
      fetchDetailsText.includes("fetch-password-secret") ||
      fetchCopy.includes("fetch-token-secret") ||
      fetchCopy.includes("fetch-password-secret")
    ) {
      throw new Error(`Truncated FETCH JSON error leaked a secret: ${JSON.stringify({ fetchDetailsText, fetchCopy })}`);
    }
    await fetchCard.locator('[data-http-error-action="retry"]').click();
    await waitForPageCondition(
      "FETCH download error Retry starts another download",
      () => window.__xferryFetchRequestCount === 2
    );
    await page.locator("#tab-request").focus();
    await fetchCard.waitFor({ state: "visible" });
    await fetchCard.locator('[data-http-error-action="close"]').click();
    await fetchCard.waitFor({ state: "detached" });
    await waitForPageCondition(
      "FETCH download error Close focus restores the original trigger",
      () => document.activeElement?.id === "themeBtn"
    );
    await page.evaluate(() => {
      window.XMLHttpRequest = window.__xferryHttpErrorOriginalXhr;
      delete window.__xferryHttpErrorOriginalXhr;
      delete window.__xferryFetchRequestCount;
    });

    return {
      hostileHtml: "text-only",
      redaction: "display-and-copy",
      retryCount,
      bounds: truncation,
      closeAndEscapeFocusRestore: true,
      genericRequestIntegration: true,
      fetchDownloadIntegration: true,
    };
  }

  async function runRecoveryJourney() {
    await page.locator("#tab-upload").click();
    await waitForTabState("upload", { focused: true });
    await switchLanguage("en");

    const basicInitial = await page.evaluate(async () => {
      const app = window.XferryApp;
      const http = app.service("http");
      const calls = [];
      const originalAdapter = http["set-adapter"]((method, url, body, headers, progress, options) => {
        const requestUrl = String(url);
        calls.push({ method, path: new URL(requestUrl, location.href).pathname });
        if (requestUrl.includes("/uploads/")) {
          return Promise.resolve(new Response(JSON.stringify({ error: {
            code: "forbidden", message: "Forbidden upload", field: null, details: {},
          } }), {
            status: 403,
            statusText: "Forbidden",
            headers: {
              "Content-Type": "application/json",
              "X-Request-ID": "basic-403",
            },
          }));
        }
        return Promise.reject(new Error(`Unexpected recovery request: ${method} ${requestUrl}`));
      });
      app.invoke("upload", "set-method", "POST");
      app.invoke("upload", "set-profile", "raw-url");
      app.invoke("upload", "handle-files", [
        new File(["denied"], "single-403.txt", { type: "text/plain" }),
      ]);
      await app.invoke("upload", "send");
      const result = {
        responseText: document.getElementById("uploadResponseArea")?.textContent || "",
        summaryStatus: document.querySelector(
          '[data-tool-summary-scope="upload"] [data-tool-summary-field="status"] .tool-result__meta-value'
        )?.textContent || "",
        state: app.getState("upload"),
        calls,
      };
      http["set-adapter"](originalAdapter);
      return result;
    });

    if (basicInitial.summaryStatus !== "403 Forbidden") {
      throw new Error(`Basic single 403 did not retain the real status: ${JSON.stringify(basicInitial)}`);
    }

    const recovery = await page.evaluate(async () => {
      const app = window.XferryApp;
      const http = app.service("http");
      const uploadCalls = [];
      const infoResponses = [];
      const infoPaths = [];
      const advancedRequests = [];
      let advancedAttempts = 0;
      const uploadFailureFixtures = new Map();
      let advancedRetryShouldSucceed = false;
      const sessionIssuedAt = Date.now();
      const sessionMetadata = {
        prefix: "/advanced",
        decoder: "auto",
        diagnostic_headers: true,
        created_at: new Date(sessionIssuedAt).toISOString(),
        expires_at: new Date(sessionIssuedAt + 60 * 60 * 1000).toISOString(),
        idle_timeout_seconds: 900,
      };
      const originalAdapter = http["set-adapter"]((method, url, body, headers, progress, options) => {
        const requestUrl = String(url);
        const pathname = new URL(requestUrl, location.href).pathname;
        if (
          pathname === "/_xferry/advanced-sessions" ||
          pathname === "/_xferry/advanced-sessions/current"
        ) {
          const payload = {
            advanced_session: method === "POST"
              ? { token: "R".repeat(43), ...sessionMetadata }
              : sessionMetadata,
          };
          return Promise.resolve(new Response(JSON.stringify(payload), {
            status: method === "POST" ? 201 : 200,
            headers: { "Content-Type": "application/json" },
          }));
        }
        if (method === "INFO") {
          infoPaths.push(pathname);
          const next = infoResponses.shift();
          if (!next) {
            return Promise.reject(new Error(`Missing INFO fixture for ${pathname}`));
          }
          return Promise.resolve(next);
        }
        if (pathname.startsWith("/uploads/")) {
          uploadCalls.push(pathname);
          const fixture = uploadFailureFixtures.get(pathname);
          if (fixture?.kind === "network") {
            return Promise.reject(new Error(fixture.message));
          }
          if (fixture?.kind === "http") {
            return Promise.resolve(new Response(JSON.stringify({ error: {
              code: "forbidden", message: fixture.message, field: null, details: {},
            } }), {
              status: fixture.status,
              statusText: fixture.statusText,
              headers: {
                "Content-Type": "application/json",
                "X-Request-ID": `upload-${uploadCalls.length}`,
              },
            }));
          }
          return Promise.resolve(new Response(JSON.stringify({ error: {
            code: "forbidden", message: `Denied ${pathname}`, field: null, details: {},
          } }), {
            status: 403,
            statusText: "Forbidden",
            headers: {
              "Content-Type": "application/json",
              "X-Request-ID": `upload-${uploadCalls.length}`,
            },
          }));
        }
        advancedAttempts += 1;
        advancedRequests.push({ method, pathname });
        if (advancedRetryShouldSucceed) {
          return Promise.resolve(new Response(JSON.stringify({
            file: {
              name: "retry-succeeded.bin", path: "/uploads/retry-succeeded.bin", size_bytes: 1,
              size_human: "1 B", content_type: "application/octet-stream",
              uploaded_at: "2026-08-14T00:00:00+00:00", sha256: "a".repeat(64),
            },
            upload: { kind: "advanced" },
          }), {
            status: 200,
            statusText: "OK",
            headers: { "Content-Type": "application/json" },
          }));
        }
        return Promise.resolve(new Response(JSON.stringify({ error: {
          code: "forbidden", message: "must-not-succeed", field: null, details: {},
        } }), {
          status: 403,
          statusText: "Forbidden",
          headers: { "Content-Type": "application/json", "X-Request-ID": "advanced-403" },
        }));
      });

      const waitForUploadIdle = async () => {
        for (let attempt = 0; attempt < 50; attempt += 1) {
          if (app.getState("upload").actionPhase === "idle") {
            return;
          }
          await new Promise(resolve => setTimeout(resolve, 10));
        }
        throw new Error("Basic upload retry did not become idle");
      };
      const closeError = (host) => app.service("http-errors").close(host, { restore: false });
      const file = (name, contents = "denied") => new File([contents], name, { type: "text/plain" });

      app.invoke("upload", "handle-files", [
        file("all-failed-a.txt"),
        file("all-failed-b.txt"),
      ]);
      await app.invoke("upload", "send");
      const uploadResponseText = document.getElementById("uploadResponseArea")?.textContent || "";
      const failedRows = Array.from(document.querySelectorAll("#fileList .file-item"));
      const failedRowControls = failedRows.map((row) => ({
        details: Boolean(row.querySelector("[data-upload-error-details-index]")),
        retry: Boolean(row.querySelector("[data-upload-retry-index]")),
        remove: Boolean(row.querySelector("[data-remove-index]")),
      }));

      app.invoke("upload", "handle-files", [file("all-failed-a.txt")]);
      const reselectionRow = Array.from(document.querySelectorAll("#fileList .file-item"))
        .find((row) => row.textContent.includes("all-failed-a.txt"));
      const reselectionReset = Boolean(
        reselectionRow &&
        reselectionRow.querySelector(".file-status")?.textContent === "Pending" &&
        !reselectionRow.querySelector("[data-upload-error-details-index]")
      );

      await app.invoke("upload", "send");
      let retryFailureRow = Array.from(document.querySelectorAll("#fileList .file-item"))
        .find((row) => row.textContent.includes("all-failed-a.txt"));
      const retryButton = retryFailureRow?.querySelector("[data-upload-retry-index]");
      retryButton?.click();
      await waitForUploadIdle();
      const retryOnlyCalls = uploadCalls.slice(-1);
      retryFailureRow = Array.from(document.querySelectorAll("#fileList .file-item"))
        .find((row) => row.textContent.includes("all-failed-a.txt"));
      const detailsButton = retryFailureRow?.querySelector("[data-upload-error-details-index]");
      detailsButton?.click();
      const uploadCard = document.querySelector("#uploadHttpErrorHost .http-error-card");
      const detailsCardStatus = uploadCard?.textContent || "";
      uploadCard?.querySelector('[data-http-error-action="close"]')?.click();
      const closeFocusRestored = Boolean(document.activeElement?.matches("[data-upload-error-details-index]"));
      detailsButton?.click();
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
      const escapeFocusRestored = Boolean(document.activeElement?.matches("[data-upload-error-details-index]"));
      detailsButton?.click();
      document.querySelector("#uploadHttpErrorHost [data-http-error-action=\"retry\"]")?.click();
      await waitForUploadIdle();
      const retryCardOnlyCalls = uploadCalls.slice(-1);
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
      const retryEscapeFocusRestored = Boolean(document.activeElement?.matches("[data-upload-error-details-index]"));
      closeError("uploadHttpErrorHost");

      const findUploadRow = (name) => Array.from(document.querySelectorAll("#fileList .file-item"))
        .find((row) => row.textContent.includes(name));
      const activeErrorRow = findUploadRow("all-failed-a.txt");
      activeErrorRow?.querySelector("[data-upload-error-details-index]")?.click();
      findUploadRow("all-failed-b.txt")?.querySelector("[data-remove-index]")?.click();
      const differentRemovalKeepsActiveCard = Boolean(
        document.querySelector("#uploadHttpErrorHost .http-error-card")?.textContent.includes("all-failed-a.txt")
      );
      findUploadRow("all-failed-a.txt")?.querySelector("[data-remove-index]")?.click();
      const removedErrorCardClosed = !document.querySelector("#uploadHttpErrorHost .http-error-card");
      const removedRetryCallsBefore = uploadCalls.length;
      document.querySelector("#uploadHttpErrorHost [data-http-error-action=\"retry\"]")?.click();
      await new Promise(resolve => setTimeout(resolve, 25));
      const removedRetryDidNotSend = uploadCalls.length === removedRetryCallsBefore;
      closeError("uploadHttpErrorHost");
      findUploadRow("single-403.txt")?.querySelector("[data-remove-index]")?.click();

      const getUploadSummary = () => {
        const value = document.querySelector(
          '[data-tool-summary-scope="upload"] [data-tool-summary-field="status"] .tool-result__meta-value'
        );
        const inspectorState = app.service("inspector").getInspectorState("upload");
        return {
          phase: document.querySelector('[data-tool-summary-scope="upload"]')?.dataset.phase || "",
          status: value?.textContent || "",
          danger: Boolean(value?.classList.contains("tool-result__meta-value--danger")),
          responseStatus: inspectorState?.response?.status ?? null,
        };
      };
      uploadFailureFixtures.set("/uploads/status-zero.txt", {
        kind: "network",
        message: "offline status zero",
      });
      app.invoke("upload", "handle-files", [file("status-zero.txt")]);
      await app.invoke("upload", "send");
      const pureStatusZero = getUploadSummary();
      closeError("uploadHttpErrorHost");
      findUploadRow("status-zero.txt")?.querySelector("[data-remove-index]")?.click();

      uploadFailureFixtures.set("/uploads/status-mixed-zero.txt", {
        kind: "network",
        message: "mixed offline",
      });
      uploadFailureFixtures.set("/uploads/status-mixed-forbidden.txt", {
        kind: "http",
        status: 403,
        statusText: "Forbidden",
        message: "mixed forbidden",
      });
      app.invoke("upload", "handle-files", [
        file("status-mixed-zero.txt"),
        file("status-mixed-forbidden.txt"),
      ]);
      await app.invoke("upload", "send");
      const mixedStatusZeroAndForbidden = getUploadSummary();
      closeError("uploadHttpErrorHost");

      document.getElementById("tab-opsec")?.click();
      await new Promise(resolve => setTimeout(resolve, 0));
      app.invoke("advanced", "set-file", file("advanced-403.bin"));
      await new Promise(resolve => setTimeout(resolve, 0));
      await app.invoke("advanced", "refresh-preview");
      await app.invoke("advanced", "send");
      const advancedPhase = document.querySelector('[data-tool-summary-scope="opsec"]')?.dataset.phase || "";
      const advancedCardText = document.querySelector("#opsecHttpErrorHost .http-error-card")?.textContent || "";
      document.getElementById("opsecMethodInput").value = "CHANGED-AFTER-ERROR";
      document.querySelector("#opsecHttpErrorHost [data-http-error-action=\"retry\"]")?.click();
      for (let attempt = 0; attempt < 50; attempt += 1) {
        if (advancedAttempts === 2 && !document.getElementById("opsecUploadBtn")?.disabled) {
          break;
        }
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      const advancedRetryFocusCard = document.querySelector("#opsecHttpErrorHost .http-error-card");
      const advancedRetryOriginDisabled = Boolean(document.getElementById("opsecUploadBtn")?.disabled);
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
      const advancedRetryFocusRestored = document.activeElement?.id === "opsecUploadBtn";
      closeError("opsecHttpErrorHost");

      document.getElementById("opsecMethodInput").value = "RETRY-SUCCESS";
      document.getElementById("opsecMethodInput").dispatchEvent(new Event("input", { bubbles: true }));
      await app.invoke("advanced", "refresh-preview");
      await app.invoke("advanced", "send");
      const advancedSuccessRetryCard = document.querySelector("#opsecHttpErrorHost .http-error-card");
      advancedRetryShouldSucceed = true;
      advancedSuccessRetryCard?.querySelector('[data-http-error-action="retry"]')?.click();
      for (let attempt = 0; attempt < 50; attempt += 1) {
        if (
          !document.querySelector("#opsecHttpErrorHost .http-error-card") &&
          !document.getElementById("opsecUploadBtn")?.disabled
        ) {
          break;
        }
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      const advancedSuccessfulRetryCardClosed = !document.querySelector(
        "#opsecHttpErrorHost .http-error-card"
      );
      const advancedSuccessfulRetryFocusRestored = document.activeElement?.id === "opsecUploadBtn";

      infoResponses.push(
        new Response(JSON.stringify({
          entry: { kind: "directory", path: "/cached" },
          page: { total_items: 1 },
          contents: [{ name: "cached.txt", kind: "file" }],
        }), { status: 200, statusText: "OK", headers: { "Content-Type": "application/json" } }),
        new Response(JSON.stringify({ error: {
          code: "forbidden", message: "Forbidden JSON", field: null, details: {},
        } }), {
          status: 403,
          statusText: "Forbidden",
          headers: { "Content-Type": "application/json", "X-Request-ID": "info-json-403" },
        }),
        new Response('<img src=x onerror="window.__infoHostileHtmlExecuted=true">', {
          status: 403,
          statusText: "Forbidden",
          headers: { "Content-Type": "text/html", "X-Request-ID": "info-html-403" },
        }),
        new Response(JSON.stringify({
          entry: { kind: "directory", path: "/cached" },
          page: { total_items: 1 },
          contents: [{ name: "fresh.txt", kind: "file" }],
        }), { status: 200, statusText: "OK", headers: { "Content-Type": "application/json" } }),
      );
      const pathInput = document.getElementById("browsePathInput");
      window.__infoHostileHtmlExecuted = false;
      pathInput.value = "/cached";
      await app.invoke("files", "browse");
      pathInput.value = "/json-forbidden";
      await app.invoke("files", "browse");
      const staleAfterJson = {
        status: document.getElementById("filesBrowseStatus")?.textContent || "",
        names: Array.from(document.querySelectorAll("#serverFiles .file-name")).map(node => node.textContent),
        actionsDisabled: Array.from(document.querySelectorAll("#serverFiles button, #serverFiles input"))
          .every(node => node.disabled),
        cardText: document.querySelector("#filesHttpErrorHost .http-error-card")?.textContent || "",
      };
      closeError("filesHttpErrorHost");
      pathInput.value = "/html-forbidden";
      await app.invoke("files", "browse");
      const staleAfterHtml = {
        status: document.getElementById("filesBrowseStatus")?.textContent || "",
        names: Array.from(document.querySelectorAll("#serverFiles .file-name")).map(node => node.textContent),
        cardText: document.querySelector("#filesHttpErrorHost .http-error-card")?.textContent || "",
        hostileExecuted: Boolean(window.__infoHostileHtmlExecuted),
      };
      const filesCard = document.querySelector("#filesHttpErrorHost .http-error-card");
      pathInput.value = "/changed-after-error";
      filesCard?.querySelector('[data-http-error-action="retry"]')?.click();
      await new Promise(resolve => setTimeout(resolve, 25));
      const freshAfterRetry = {
        status: document.getElementById("filesBrowseStatus")?.textContent || "",
        names: Array.from(document.querySelectorAll("#serverFiles .file-name")).map(node => node.textContent),
        actionsDisabled: Array.from(document.querySelectorAll("#serverFiles button, #serverFiles input"))
          .some(node => node.disabled),
      };
      closeError("filesHttpErrorHost");
      http["set-adapter"](originalAdapter);

      return {
        uploadResponseText,
        failedRowControls,
        reselectionReset,
        retryOnlyCalls,
        detailsCardStatus,
        closeFocusRestored,
        escapeFocusRestored,
        retryCardOnlyCalls,
        retryEscapeFocusRestored,
        differentRemovalKeepsActiveCard,
        removedErrorCardClosed,
        removedRetryDidNotSend,
        pureStatusZero,
        mixedStatusZeroAndForbidden,
        advancedAttempts,
        advancedRequests,
        advancedPhase,
        advancedCardText,
        advancedRetryFocusRestored,
        advancedRetryOriginDisabled,
        advancedRetryCardText: advancedRetryFocusCard?.textContent || "",
        advancedSuccessfulRetryCardClosed,
        advancedSuccessfulRetryFocusRestored,
        infoPaths,
        staleAfterJson,
        staleAfterHtml,
        freshAfterRetry,
      };
    });

    if (
      !recovery.uploadResponseText.includes("403 Forbidden") ||
      !recovery.uploadResponseText.includes("all-failed-a.txt") ||
      !recovery.uploadResponseText.includes("all-failed-b.txt") ||
      recovery.failedRowControls.length !== 3 ||
      recovery.failedRowControls.some(control => !control.details || !control.retry || !control.remove) ||
      !recovery.reselectionReset ||
      recovery.retryOnlyCalls.join(",") !== "/uploads/all-failed-a.txt" ||
      !recovery.detailsCardStatus.includes("403 Forbidden") ||
      !recovery.closeFocusRestored ||
      !recovery.escapeFocusRestored ||
      recovery.retryCardOnlyCalls.join(",") !== "/uploads/all-failed-a.txt" ||
      !recovery.retryEscapeFocusRestored ||
      !recovery.differentRemovalKeepsActiveCard ||
      !recovery.removedErrorCardClosed ||
      !recovery.removedRetryDidNotSend ||
      recovery.pureStatusZero.phase !== "error" ||
      recovery.pureStatusZero.responseStatus !== 0 ||
      recovery.pureStatusZero.status === "201 Error" ||
      !recovery.pureStatusZero.danger ||
      recovery.mixedStatusZeroAndForbidden.phase !== "error" ||
      recovery.mixedStatusZeroAndForbidden.responseStatus !== 403 ||
      recovery.mixedStatusZeroAndForbidden.status !== "403 Forbidden" ||
      !recovery.mixedStatusZeroAndForbidden.danger
    ) {
      throw new Error(`Basic recovery controls/regression failed: ${JSON.stringify(recovery)}`);
    }
    if (
      recovery.advancedAttempts !== 4 ||
      recovery.advancedPhase !== "error" ||
      !recovery.advancedCardText.includes("403 Forbidden") ||
      !recovery.advancedRetryCardText.includes("403 Forbidden") ||
      !recovery.advancedRetryFocusRestored ||
      !recovery.advancedSuccessfulRetryCardClosed ||
      !recovery.advancedSuccessfulRetryFocusRestored ||
      recovery.advancedRequests.length !== 4 ||
      recovery.advancedRequests[0].method !== recovery.advancedRequests[1].method ||
      recovery.advancedRequests[0].pathname !== recovery.advancedRequests[1].pathname
    ) {
      throw new Error(`Advanced HTTP/application success gate failed: ${JSON.stringify(recovery)}`);
    }
    if (
      !recovery.staleAfterJson.status.includes("/cached") ||
      recovery.staleAfterJson.names.join(",") !== "cached.txt" ||
      !recovery.staleAfterJson.actionsDisabled ||
      !recovery.staleAfterJson.cardText.includes("403 Forbidden") ||
      !recovery.staleAfterHtml.status.includes("/cached") ||
      recovery.staleAfterHtml.names.join(",") !== "cached.txt" ||
      !recovery.staleAfterHtml.cardText.includes("403 Forbidden") ||
      recovery.staleAfterHtml.hostileExecuted ||
      recovery.infoPaths.at(-1) !== "/html-forbidden" ||
      recovery.freshAfterRetry.names.join(",") !== "fresh.txt" ||
      recovery.freshAfterRetry.actionsDisabled
    ) {
      throw new Error(`Files INFO recovery/stale list failed: ${JSON.stringify(recovery)}`);
    }

    return recovery;
  }

  async function runFilesJourney() {
    const uploadName = fixtureName(uploadFilePath);
    const unicodeUploadName = fixtureName(unicodeUploadFilePath);
    await uploadViaDom(uploadName, uploadFilePath);
    await uploadViaDom(unicodeUploadName, unicodeUploadFilePath);
    await browseUploadsAndAssert(uploadName);
    await waitForLiveRegionText("filesResponseAreaLive", "INFO /uploads 200 OK", 10000);
    await assertFileActionAccessibleNames(uploadName);
    await fetchViaServerFilesAndAssert(uploadName);
    await assertSmuggleSearchableComboboxContract(uploadName);
    const filenameResolution = await assertFetchDownloadFilenameResolution(unicodeUploadName);
    await assertFileDisclosureInteractions(uploadName, unicodeUploadName);
    const unicodeInfoPath = await infoViaServerFilesAndAssert(unicodeUploadName, { capture: true });
    await switchLanguage("en");
    const englishInfoPath = await infoViaServerFilesAndAssert(uploadName, {
      activation: "enter",
      close: "escape",
      capture: true,
    });
    const smugglePopupUrl = await smuggleViaServerFilesAndAssert(uploadName);
    await switchLanguage("ru");
    const infoPath = await infoViaServerFilesAndAssert(uploadName, {
      activation: "space",
      expectRequest: false,
    });
    let uploadsCleared = false;
    let cleanupMode = "clear-uploads";
    const deletedArtifacts = [];
    if (externalTarget) {
      cleanupMode = "targeted";
      await browseUploadsAndAssert(unicodeUploadName);
      await deleteViaServerFilesAndAssert(unicodeUploadName);
      deletedArtifacts.push(unicodeUploadName);
    }
    await browseUploadsAndAssert(uploadName);
    await assertDeleteDialogKeyboardContract(uploadName);
    await deleteViaServerFilesAndAssert(uploadName);
    if (externalTarget) {
      deletedArtifacts.push(uploadName);
    } else {
      await clearUploadsViaUiAndAssertSummaryPersistence();
      uploadsCleared = true;
    }
    return {
      uploadedFile: uploadName,
      unicodeUploadedFile: unicodeUploadName,
      downloadedFile: uploadName,
      filenameResolution,
      unicodeInfoPath,
      englishInfoPath,
      smugglePopupUrl,
      infoPath,
      deletedFile: uploadName,
      deletedArtifacts,
      cleanupMode,
      uploadsCleared,
    };
  }

  async function runSmuggleJourney() {
    const uploadName = fixtureName(uploadFilePath);
    const expectedContent = "browser smoke upload\n";
    await uploadViaDom(uploadName, uploadFilePath);
    await browseUploadsAndAssert(uploadName);

    const smuggleResults = [];
    for (const encryption of ["none", "xor", "aes"]) {
      smuggleResults.push(await smuggleViaModalAndAssert(uploadName, encryption, {
        mode: "simple",
        expectedContent,
      }));
    }
    smuggleResults.push(await smuggleViaModalAndAssert(uploadName, "aes", {
      mode: "constructor",
      expectedContent,
    }));

    await browseUploadsAndAssert(uploadName);
    await deleteViaServerFilesAndAssert(uploadName);
    return {
      uploadedFile: uploadName,
      deletedFile: uploadName,
      smuggleResults,
    };
  }

  async function runAdvancedSessionJourney() {
    await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await page.locator("#tab-opsec").click();
    await waitForTabState("opsec", { focused: true });
    await switchLanguage("en");
    await waitForAdvancedSessionReady();

    await page.locator("#opsecMethodInput").fill("POST");
    await page.locator("#opsecProfileSelect").selectOption("body-json");
    await page.locator("#opsecFileInput").setInputFiles(opsecUploadFilePath);
    await waitForPageCondition(
      "advanced canonical preview is session-aligned",
      () => {
        const state = window.XferryApp.getState("advanced");
        const session = window.XferryApp.service("advanced-session").getSnapshot();
        return state.previewPlanReady === true &&
          state.previewPending === false &&
          state.sessionActive === true &&
          state.previewSessionExpiresAt === session.expires_at &&
          document.getElementById("opsecUploadBtn")?.disabled === false;
      },
      null,
      15000
    );

    const committedPreview = await page.evaluate(async ([fileSize]) => {
      const app = window.XferryApp;
      const workflowState = app.getState("advanced");
      const request = app.service("inspector").getInspectorState("opsec")?.request || {};
      const bytes = new Uint8Array(fileSize).fill("A".charCodeAt(0));
      let binary = "";
      const chunkSize = 8192;
      for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
      }
      const expectedBody = JSON.stringify({
        data: btoa(binary),
        encoding: "base64",
        encryption: "none",
      });
      const previewBody = request.body?.text || "";
      const redactedData = JSON.parse(previewBody).data;
      const headers = Object.fromEntries(
        Object.entries(request.headers || {})
          .map(([name, value]) => [name.toLowerCase(), String(value)])
          .sort(([left], [right]) => left.localeCompare(right))
      );
      return {
        identity: workflowState.previewPlanIdentity,
        method: request.method || "",
        target: request.path || "",
        headers,
        bodyBytes: Array.from(new TextEncoder().encode(expectedBody)),
        redactedBody: previewBody,
        expectedRedactedBody: JSON.stringify({
          data: redactedData,
          encoding: "base64",
          encryption: "none",
        }),
      };
    }, [1126]);
    if (
      committedPreview.identity === null ||
      committedPreview.method !== "POST" ||
      !committedPreview.target.startsWith("/advanced/") ||
      committedPreview.headers["content-type"] !== "application/json" ||
      Object.keys(committedPreview.headers).some(
        (name) => name === "x-xferry-advanced-session"
      ) ||
      committedPreview.redactedBody !== committedPreview.expectedRedactedBody
    ) {
      throw new Error(
        `Advanced committed preview snapshot failed: ${JSON.stringify({
          identity: committedPreview.identity,
          method: committedPreview.method,
          target: committedPreview.target,
          headers: committedPreview.headers,
          redactedBody: committedPreview.redactedBody,
        })}`
      );
    }

    const dataRequestPromise = page.waitForRequest((request) => {
      const pathname = requestPathname(request);
      return request.method() === "POST" &&
        pathname.startsWith("/advanced/") &&
        Boolean(request.headers()["x-xferry-advanced-session"]);
    }, { timeout: 15000 });
    const dataResponsePromise = page.waitForResponse((response) => {
      const request = response.request();
      const pathname = requestPathname(request);
      return request.method() === "POST" &&
        pathname.startsWith("/advanced/") &&
        Boolean(request.headers()["x-xferry-advanced-session"]);
    }, { timeout: 15000 });
    await page.locator("#opsecUploadBtn").click();
    const [dataRequest, dataResponse] = await Promise.all([
      dataRequestPromise,
      dataResponsePromise,
    ]);
    const requestHeaders = await dataRequest.allHeaders();
    const responseHeaders = await dataResponse.allHeaders();
    const token = requestHeaders["x-xferry-advanced-session"] || "";
    const requestBody = dataRequest.postData() || "";
    const requestBodyBytes = Array.from(dataRequest.postDataBuffer() || []);
    await waitForPageCondition(
      "advanced canonical upload completes",
      () => (
        window.XferryApp.service("inspector").getInspectorState("opsec")?.response?.phase ===
        "complete"
      ),
      null,
      15000
    );
    const dispatchedPreviewIdentityAfterSend = await page.evaluate(
      () => window.XferryApp.getState("advanced").lastDispatchedPlanIdentity
    );

    const actualTarget = String(dataRequest.url())
      .replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]+/i, "")
      .split("#", 1)[0] || "/";
    const actualCanonicalHeaders = Object.fromEntries(
      Object.entries(requestHeaders)
        .filter(([name]) => {
          const normalized = name.toLowerCase();
          return normalized === "content-type" || (
            normalized.startsWith("x-xferry-") &&
            normalized !== "x-xferry-advanced-session"
          );
        })
        .map(([name, value]) => [name.toLowerCase(), String(value)])
        .sort(([left], [right]) => left.localeCompare(right))
    );
    const previewSendIdentity = {
      sameDispatchedIdentity: dispatchedPreviewIdentityAfterSend === committedPreview.identity,
      exactMethod: dataRequest.method() === committedPreview.method,
      exactTarget: actualTarget === committedPreview.target,
      exactCanonicalHeaders: JSON.stringify(actualCanonicalHeaders) ===
        JSON.stringify(committedPreview.headers),
      exactBodyBytes: JSON.stringify(requestBodyBytes) ===
        JSON.stringify(committedPreview.bodyBytes),
    };
    if (Object.values(previewSendIdentity).some((matches) => matches !== true)) {
      throw new Error(
        `Advanced committed preview/send identity failed: ${JSON.stringify({
          previewSendIdentity,
          committedIdentity: committedPreview.identity,
          dispatchedPreviewIdentityAfterSend,
          committedMethod: committedPreview.method,
          actualMethod: dataRequest.method(),
          committedTarget: committedPreview.target,
          actualTarget,
          committedHeaders: committedPreview.headers,
          actualCanonicalHeaders,
          committedBodySize: committedPreview.bodyBytes.length,
          actualBodySize: requestBodyBytes.length,
        })}`
      );
    }

    const safety = await page.evaluate(async ([secret]) => {
      const state = window.XferryApp.service("inspector").getInspectorState("opsec");
      const inspector = window.XferryApp.service("inspector");
      const rendered = document.documentElement.innerText;
      const requestPreview = document.getElementById("opsecRequestArea")?.innerText || "";
      const inspectorExport = inspector.buildRawMessageForExport(
        state?.request || {},
        "request"
      );
      let indexedDbText = "";
      if (typeof indexedDB?.databases === "function") {
        const databases = await indexedDB.databases();
        for (const info of databases) {
          if (!info.name) continue;
          const database = await new Promise((resolve, reject) => {
            const request = indexedDB.open(info.name);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
          });
          for (const storeName of Array.from(database.objectStoreNames)) {
            const values = await new Promise((resolve, reject) => {
              const transaction = database.transaction(storeName, "readonly");
              const request = transaction.objectStore(storeName).getAll();
              request.onsuccess = () => resolve(request.result);
              request.onerror = () => reject(request.error);
            });
            indexedDbText += JSON.stringify(values);
          }
          database.close();
        }
      }
      return {
        active: window.XferryApp.service("advanced-session").getSnapshot().active,
        tokenAbsentFromDom: !rendered.includes(secret),
        tokenAbsentFromPreview: !requestPreview.includes(secret),
        tokenAbsentFromInspectorState: !JSON.stringify(state).includes(secret),
        tokenAbsentFromInspectorExport: !inspectorExport.includes(secret),
        tokenAbsentFromStorage: ![
          ...Object.values(localStorage),
          ...Object.values(sessionStorage),
        ].join("\n").includes(secret),
        tokenAbsentFromCookies: !document.cookie.includes(secret),
        tokenAbsentFromIndexedDb: !indexedDbText.includes(secret),
        tokenAbsentFromUrl: !location.href.includes(secret),
        sessionHeaderNotPreviewed: !requestPreview.includes("X-XFerry-Advanced-Session"),
        responseSummary: state?.response?.summaryText || "",
      };
    }, [token]);
    const parsedBody = JSON.parse(requestBody);
    const requestHeaderNames = Object.keys(requestHeaders);
    const tokenAbsentFromLogs = !JSON.stringify(browserIssues).includes(token);
    const canonicalRequest = {
      path: requestPathname(dataRequest),
      sessionHeaderAttached: /^[A-Za-z0-9_-]{43}$/.test(token),
      explicitNone: parsedBody.encryption === "none",
      canonicalData: typeof parsedBody.data === "string" && parsedBody.data.length > 0,
      diagnosticHeader: dataResponse.status() === 201 &&
        responseHeaders["x-xferry-handler"] === "advanced",
      forbiddenNoneMetadata: ["key", "key_is_base64", "hmac"].some(
        (name) => Object.hasOwn(parsedBody, name)
      ),
      legacyHeaderPresent: requestHeaderNames.some(
        (name) => /^x-(?:d|e|k|kb64|n|h|encoding|http-method-override)$/i.test(name)
      ),
    };
    if (
      !canonicalRequest.sessionHeaderAttached ||
      !canonicalRequest.explicitNone ||
      !canonicalRequest.canonicalData ||
      !canonicalRequest.diagnosticHeader ||
      canonicalRequest.forbiddenNoneMetadata ||
      canonicalRequest.legacyHeaderPresent ||
      safety.active !== true ||
      !safety.tokenAbsentFromDom ||
      !safety.tokenAbsentFromPreview ||
      !safety.tokenAbsentFromInspectorState ||
      !safety.tokenAbsentFromInspectorExport ||
      !safety.tokenAbsentFromStorage ||
      !safety.tokenAbsentFromCookies ||
      !safety.tokenAbsentFromIndexedDb ||
      !safety.tokenAbsentFromUrl ||
      !safety.sessionHeaderNotPreviewed ||
      !tokenAbsentFromLogs
    ) {
      throw new Error(
        `Advanced session send contract failed: ${JSON.stringify({
          canonicalRequest,
          safety,
          tokenAbsentFromLogs,
        })}`
      );
    }

    const retryStateSafety = await page.evaluate(async ([secret]) => {
      const app = window.XferryApp;
      const http = app.service("http");
      const originalAdapter = http["set-adapter"]((method, url, body, headers, ...rest) => {
        const pathname = new URL(String(url), location.href).pathname;
        if (
          pathname.startsWith("/advanced/") &&
          headers?.["X-XFerry-Advanced-Session"]
        ) {
          return Promise.resolve(new Response(JSON.stringify({ error: {
            code: "retry_sink_probe",
            message: "synthetic retry sink failure",
            field: null,
            details: {},
          } }), {
            status: 503,
            statusText: "Service Unavailable",
            headers: { "Content-Type": "application/json" },
          }));
        }
        return originalAdapter(method, url, body, headers, ...rest);
      });
      try {
        app.invoke("advanced", "set-file", new File(
          [new TextEncoder().encode("retry sink payload")],
          "retry-sink.bin",
          { type: "application/octet-stream" }
        ));
        await app.invoke("advanced", "refresh-preview");
        await app.invoke("advanced", "send");
        const card = document.querySelector("#opsecHttpErrorHost .http-error-card");
        const inspectorState = app.service("inspector").getInspectorState("opsec");
        return {
          cardPresent: Boolean(card),
          tokenAbsentFromCard: !String(card?.textContent || "").includes(secret),
          tokenAbsentFromRetryInspector: !JSON.stringify(inspectorState).includes(secret),
        };
      } finally {
        http["set-adapter"](originalAdapter);
      }
    }, [token]);
    if (
      retryStateSafety.cardPresent !== true ||
      retryStateSafety.tokenAbsentFromCard !== true ||
      retryStateSafety.tokenAbsentFromRetryInspector !== true
    ) {
      throw new Error(`Advanced retry sink setup failed: ${JSON.stringify(retryStateSafety)}`);
    }

    const revokeResponsePromise = page.waitForResponse((response) => (
      response.request().method() === "DELETE" &&
      requestPathname(response.request()) === "/_xferry/advanced-sessions/current"
    ), { timeout: 10000 });
    await page.locator("#advancedSessionRevokeBtn").click();
    const revokeResponse = await revokeResponsePromise;
    const revokePayload = await revokeResponse.json();
    await waitForPageCondition(
      "advanced session inactive after revoke",
      () => {
        const snapshot = window.XferryApp.service("advanced-session").getSnapshot();
        return snapshot.active === false &&
          document.getElementById("advancedSessionPanel")?.dataset.sessionPhase === "inactive" &&
          document.getElementById("advancedSessionStatus")?.textContent?.includes(
            "Advanced session inactive"
          );
      },
      null,
      10000
    );
    const rejectedReuseResponse = await page.request.get(
      `${rootUrl.replace(/\/$/, "")}/_xferry/advanced-sessions/current`,
      { headers: { "X-XFerry-Advanced-Session": token } }
    );
    const rejectedReusePayload = await rejectedReuseResponse.json();
    const rejectedReuse = {
      status: rejectedReuseResponse.status(),
      code: rejectedReusePayload?.error?.code || "",
    };
    const sendDisabledAfterRevoke = await page.locator("#opsecUploadBtn").isDisabled();
    let retryDataRequests = 0;
    const countRetryDataRequest = (request) => {
      if (
        requestPathname(request).startsWith("/advanced/") &&
        Boolean(request.headers()["x-xferry-advanced-session"])
      ) {
        retryDataRequests += 1;
      }
    };
    page.on("request", countRetryDataRequest);
    await page.locator(
      "#opsecHttpErrorHost [data-http-error-action='retry']"
    ).click();
    await waitForPageCondition(
      "revoked Advanced retry is rejected before data send",
      () => {
        const response = window.XferryApp.service("inspector")
          .getInspectorState("opsec")?.response;
        return response?.phase === "error" &&
          String(response?.summaryText || "").includes("Advanced session inactive");
      },
      null,
      10000
    );
    page.off("request", countRetryDataRequest);
    const retryStateTokenAbsent = retryDataRequests === 0;
    const failedCreateState = await page.evaluate(async () => {
      const app = window.XferryApp;
      const http = app.service("http");
      const session = app.service("advanced-session");
      const originalAdapter = http["set-adapter"]((method, url, ...rest) => {
        const pathname = new URL(String(url), location.href).pathname;
        if (method === "POST" && pathname === "/_xferry/advanced-sessions") {
          return Promise.resolve(new Response(JSON.stringify({ error: {
            code: "session_create_failed",
            message: "synthetic create failure",
            field: null,
            details: {},
          } }), {
            status: 503,
            statusText: "Service Unavailable",
            headers: { "Content-Type": "application/json" },
          }));
        }
        return originalAdapter(method, url, ...rest);
      });
      try {
        await session.create();
        const snapshot = session.getSnapshot();
        return {
          active: snapshot.active,
          phase: snapshot.phase,
          hasError: Boolean(snapshot.error),
          sendDisabled: document.getElementById("opsecUploadBtn")?.disabled === true,
        };
      } finally {
        http["set-adapter"](originalAdapter);
      }
    });
    if (
      revokeResponse.status() !== 200 ||
      revokePayload?.advanced_session?.revoked !== true ||
      rejectedReuse.status !== 404 ||
      rejectedReuse.code !== "advanced_session_not_found" ||
      sendDisabledAfterRevoke !== true ||
      retryStateTokenAbsent !== true ||
      failedCreateState.active !== false ||
      failedCreateState.phase !== "inactive" ||
      failedCreateState.hasError !== true ||
      failedCreateState.sendDisabled !== true
    ) {
      throw new Error(`Advanced server revoke proof failed: ${JSON.stringify({
        revokeStatus: revokeResponse.status(),
        revokePayload,
        rejectedReuse,
        sendDisabledAfterRevoke,
        retryStateTokenAbsent,
        failedCreateState,
      })}`);
    }

    return {
      ...canonicalRequest,
      ...previewSendIdentity,
      tokenAbsentFromDom: safety.tokenAbsentFromDom,
      tokenAbsentFromPreview: safety.tokenAbsentFromPreview,
      tokenAbsentFromInspectorState: safety.tokenAbsentFromInspectorState,
      tokenAbsentFromInspectorExport: safety.tokenAbsentFromInspectorExport,
      tokenAbsentFromStorage: safety.tokenAbsentFromStorage,
      tokenAbsentFromCookies: safety.tokenAbsentFromCookies,
      tokenAbsentFromIndexedDb: safety.tokenAbsentFromIndexedDb,
      tokenAbsentFromUrl: safety.tokenAbsentFromUrl,
      tokenAbsentFromLogs,
      revokeResponseStatus: revokeResponse.status(),
      revokedTokenRejected: rejectedReuse.status === 404,
      sendDisabledAfterRevoke,
      tokenAbsentFromRetryState: retryStateTokenAbsent,
      failedCreateDisablesSend: failedCreateState.sendDisabled,
      revoked: revokePayload?.advanced_session?.revoked === true,
      responseSummary: safety.responseSummary,
    };
  }

  async function runAdvancedJourney() {
    return runAdvancedSessionJourney();
  }

  async function runAdvancedConstructorProfilesJourney() {
    await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    const profiles = await page.evaluate(async () => {
      const compiler = window.XferryApp.service("advanced-compiler");
      const bytes = new TextEncoder().encode("browser canonical compiler");
      const configurations = [
        ["body-json", "body", "json"],
        ["body-raw", "body", "raw"],
        ["body-text", "body", "text"],
        ["body-form", "body", "form"],
        ["body-xml", "body", "xml"],
        ["multipart-binary", "body", "multipart-binary"],
        ["multipart-encoded", "body", "multipart-encoded"],
        ["headers", "headers", "json"],
        ["query", "query", "json"],
        ["cookies", "cookies", "json"],
        ["path", "path", "json"],
      ];
      const results = [];
      for (const [profile, carrier, bodyFormat] of configurations) {
        const plan = await compiler.compile({
          method: "POST",
          prefix: "/advanced",
          carrier,
          bodyFormat,
          encoding: bodyFormat === "raw" ? "raw" : "base64",
          encryption: "none",
          name: "browser.txt",
          mime: bodyFormat === "raw"
            ? "application/octet-stream"
            : (bodyFormat === "text"
              ? "text/plain; charset=utf-8"
              : (bodyFormat === "xml" ? "application/xml" : "application/json")),
          partMime: "application/octet-stream",
        }, bytes);
        const headers = { ...plan.requestHeaders };
        const body = typeof plan.requestBody === "string" ? plan.requestBody : "";
        const binaryBody = plan.requestBody instanceof Uint8Array
          ? new TextDecoder().decode(plan.requestBody)
          : "";
        const multipartFields = plan.requestBody instanceof FormData
          ? Array.from(plan.requestBody.entries()).map(([name, value]) => [
            name,
            typeof value === "string"
              ? value
              : { name: value.name, type: value.type, size: value.size },
          ])
          : [];
        results.push({
          profile,
          path: plan.requestPath,
          headers,
          body,
          binaryBody,
          multipartFields,
          cookies: plan.cookieEffects.map((effect) => [effect.name, effect.value]),
        });
      }
      return results;
    });
    const byProfile = Object.fromEntries(profiles.map((profile) => [profile.profile, profile]));
    const dataBase64 = "YnJvd3NlciBjYW5vbmljYWwgY29tcGlsZXI=";
    const dataBase64Url = "YnJvd3NlciBjYW5vbmljYWwgY29tcGlsZXI";
    const expectedMetadataHeaders = {
      "X-XFerry-Encoding": "base64",
      "X-XFerry-Encryption": "none",
      "X-XFerry-Name": "browser.txt",
    };
    const exactShapes = {
      json: byProfile["body-json"]?.body === JSON.stringify({
        data: dataBase64,
        encoding: "base64",
        encryption: "none",
        name: "browser.txt",
      }),
      raw: byProfile["body-raw"]?.binaryBody === "browser canonical compiler" &&
        byProfile["body-raw"]?.headers?.["Content-Type"] === "application/octet-stream" &&
        byProfile["body-raw"]?.headers?.["X-XFerry-Encryption"] === "none" &&
        byProfile["body-raw"]?.headers?.["X-XFerry-Name"] === "browser.txt",
      text: byProfile["body-text"]?.body === "browser canonical compiler" &&
        byProfile["body-text"]?.headers?.["Content-Type"] === "text/plain; charset=utf-8" &&
        byProfile["body-text"]?.headers?.["X-XFerry-Encryption"] === "none",
      form: byProfile["body-form"]?.body ===
        `data=${encodeURIComponent(dataBase64)}&encoding=base64&encryption=none&name=browser.txt`,
      xml: byProfile["body-xml"]?.body ===
        `<upload><data>${dataBase64}</data><encoding>base64</encoding>` +
        `<encryption>none</encryption><name>browser.txt</name></upload>`,
      multipartBinary: JSON.stringify(byProfile["multipart-binary"]?.multipartFields) ===
        JSON.stringify([
          ["file", { name: "browser.txt", type: "application/octet-stream", size: 26 }],
          ["encryption", "none"],
        ]) && !Object.hasOwn(byProfile["multipart-binary"]?.headers || {}, "Content-Type"),
      multipartEncoded: JSON.stringify(byProfile["multipart-encoded"]?.multipartFields) ===
        JSON.stringify([
          ["data", dataBase64],
          ["encoding", "base64"],
          ["encryption", "none"],
          ["name", "browser.txt"],
        ]) && !Object.hasOwn(byProfile["multipart-encoded"]?.headers || {}, "Content-Type"),
      headers: byProfile.headers?.headers?.["X-XFerry-Data"] === dataBase64 &&
        Object.entries(expectedMetadataHeaders).every(
          ([name, value]) => byProfile.headers?.headers?.[name] === value
        ),
      query: byProfile.query?.path ===
        `/advanced?data=${encodeURIComponent(dataBase64)}` +
        "&encoding=base64&encryption=none&name=browser.txt",
      cookies: JSON.stringify(byProfile.cookies?.cookies) === JSON.stringify([
        ["xferry_data", dataBase64],
        ["xferry_encoding", "base64"],
        ["xferry_encryption", "none"],
        ["xferry_name", "browser.txt"],
      ]),
      path: byProfile.path?.path ===
        `/advanced/_payload/browser.txt/${dataBase64Url}?encryption=none`,
    };
    const forbiddenNoneMetadata = profiles.some((profile) => (
      /(?:^|[?&<])(?:key|key_is_base64|hmac)(?:=|>)/.test(profile.body) ||
      /(?:[?&])(?:key|key_is_base64|hmac)=/.test(profile.path) ||
      Object.keys(profile.headers).some((name) => (
        ["x-xferry-key", "x-xferry-key-is-base64", "x-xferry-hmac"]
          .includes(name.toLowerCase())
      )) ||
      profile.cookies.some(([name]) => (
        ["xferry_key", "xferry_key_is_base64", "xferry_hmac"].includes(name)
      ))
    ));
    if (
      profiles.length !== 11 ||
      Object.values(exactShapes).some((matches) => matches !== true) ||
      forbiddenNoneMetadata
    ) {
      throw new Error(`Canonical Advanced compiler profiles failed: ${JSON.stringify(profiles)}`);
    }

    await page.locator("#tab-opsec").click();
    await waitForTabState("opsec", { focused: true });
    await switchLanguage("en");
    await waitForAdvancedSessionReady();
    await page.locator("#opsecMethodInput").fill("POST");
    await page.locator("#opsecProfileSelect").selectOption("body-json");
    await page.evaluate(async () => {
      const app = window.XferryApp;
      app.invoke("advanced", "set-file", new File(
        [new TextEncoder().encode("atomic stable")],
        "atomic-stable.txt",
        { type: "text/plain", lastModified: 1 }
      ));
      await app.invoke("advanced", "refresh-preview");
    });
    await waitForPageCondition(
      "stable Advanced preview is ready before atomic promotion probe",
      () => {
        const state = window.XferryApp.getState("advanced");
        const path = window.XferryApp.service("inspector")
          .getInspectorState("opsec")?.request?.path || "";
        return state.previewPlanReady === true &&
          state.previewPending === false &&
          state.previewPlanIdentity !== null &&
          path.startsWith("/advanced/") &&
          !path.includes("?data=");
      },
      null,
      15000
    );
    const stablePreview = await page.evaluate(() => ({
      state: window.XferryApp.getState("advanced"),
      summary: document.querySelector('[data-opsec-outcome="transport"]')?.textContent || "",
      raw: document.getElementById("opsecRequestArea")?.textContent || "",
      path: window.XferryApp.service("inspector")
        .getInspectorState("opsec")?.request?.path || "",
    }));
    await page.evaluate(() => {
      const app = window.XferryApp;
      const slowFile = new File(
        [new TextEncoder().encode("atomic stale")],
        "atomic-stale.txt",
        { type: "text/plain", lastModified: 2 }
      );
      const read = slowFile.arrayBuffer.bind(slowFile);
      let release;
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      slowFile.arrayBuffer = () => gate.then(() => read());
      window.__xferryReleaseAtomicPreview = release;
      app.invoke("advanced", "set-file", slowFile);
      const profile = document.getElementById("opsecProfileSelect");
      profile.value = "query";
      profile.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await waitForPageCondition(
      "delayed Advanced previews preserve the committed surface",
      ([previousSequence]) => {
        const state = window.XferryApp.getState("advanced");
        return state.previewPending === true &&
          state.previewSequence >= previousSequence + 2;
      },
      [stablePreview.state.previewSequence],
      10000
    );
    const pendingPreview = await page.evaluate(() => ({
      state: window.XferryApp.getState("advanced"),
      summary: document.querySelector('[data-opsec-outcome="transport"]')?.textContent || "",
      raw: document.getElementById("opsecRequestArea")?.textContent || "",
      path: window.XferryApp.service("inspector")
        .getInspectorState("opsec")?.request?.path || "",
      pendingVisible: document.getElementById("opsecPreviewPending")?.hidden === false,
      summaryBusy: document.querySelector('[data-testid="opsec-outcome-summary"]')
        ?.getAttribute("aria-busy"),
    }));
    await page.evaluate(() => {
      window.XferryApp.invoke("advanced", "set-file", new File(
        [new TextEncoder().encode("atomic latest")],
        "atomic-latest.txt",
        { type: "text/plain", lastModified: 3 }
      ));
    });
    await waitForPageCondition(
      "latest Advanced preview promotes before stale reads complete",
      ([oldIdentity]) => {
        const app = window.XferryApp;
        const state = app.getState("advanced");
        const path = app.service("inspector").getInspectorState("opsec")?.request?.path || "";
        return state.previewPlanReady === true &&
          state.previewPending === false &&
          state.previewPlanIdentity !== oldIdentity &&
          path.startsWith("/advanced/") &&
          path.includes("?data=");
      },
      [stablePreview.state.previewPlanIdentity],
      15000
    );
    const promotedPreview = await page.evaluate(() => ({
      state: window.XferryApp.getState("advanced"),
      summary: document.querySelector('[data-opsec-outcome="transport"]')?.textContent || "",
      raw: document.getElementById("opsecRequestArea")?.textContent || "",
      path: window.XferryApp.service("inspector")
        .getInspectorState("opsec")?.request?.path || "",
      pendingHidden: document.getElementById("opsecPreviewPending")?.hidden !== false,
      summaryBusy: document.querySelector('[data-testid="opsec-outcome-summary"]')
        ?.getAttribute("aria-busy"),
    }));
    await page.evaluate(() => window.__xferryReleaseAtomicPreview());
    await page.waitForTimeout(100);
    const settledPreview = await page.evaluate(() => ({
      state: window.XferryApp.getState("advanced"),
      summary: document.querySelector('[data-opsec-outcome="transport"]')?.textContent || "",
      raw: document.getElementById("opsecRequestArea")?.textContent || "",
      path: window.XferryApp.service("inspector")
        .getInspectorState("opsec")?.request?.path || "",
    }));
    delete stablePreview.state.previewFingerprint;
    delete pendingPreview.state.previewFingerprint;
    delete promotedPreview.state.previewFingerprint;
    delete settledPreview.state.previewFingerprint;
    const atomicPreviewPromotion = {
      stable: stablePreview,
      pending: pendingPreview,
      promoted: promotedPreview,
      settled: settledPreview,
    };
    if (
      pendingPreview.state.previewPending !== true ||
      pendingPreview.pendingVisible !== true ||
      pendingPreview.summaryBusy !== "true" ||
      pendingPreview.state.previewPlanIdentity !== stablePreview.state.previewPlanIdentity ||
      pendingPreview.summary !== stablePreview.summary ||
      pendingPreview.raw !== stablePreview.raw ||
      pendingPreview.path !== stablePreview.path ||
      promotedPreview.state.previewPending !== false ||
      promotedPreview.pendingHidden !== true ||
      promotedPreview.summaryBusy !== "false" ||
      promotedPreview.state.previewPlanIdentity === stablePreview.state.previewPlanIdentity ||
      !/Query/i.test(promotedPreview.summary) ||
      !promotedPreview.path.startsWith("/advanced/") ||
      !promotedPreview.path.includes("?data=") ||
      settledPreview.state.previewPlanIdentity !== promotedPreview.state.previewPlanIdentity ||
      settledPreview.summary !== promotedPreview.summary ||
      settledPreview.raw !== promotedPreview.raw ||
      settledPreview.path !== promotedPreview.path
    ) {
      throw new Error(
        `Advanced preview atomic/latest-result promotion failed: ${JSON.stringify(atomicPreviewPromotion)}`
      );
    }
    await page.evaluate(async () => {
      delete window.__xferryReleaseAtomicPreview;
      const app = window.XferryApp;
      app.invoke("advanced", "set-file", null);
      await app.service("advanced-session").revoke();
    });
    return {
      profiles: profiles.map((profile) => profile.profile),
      exactShapes,
      forbiddenNoneMetadata,
      atomicPreviewPromotion,
    };
  }

  async function runNotepadJourney() {
    const uploadName = uploadFilePath.split(/[\\/]/).pop();
    const uploadPathToPreserve = `/uploads/${uploadName}`;
    await uploadViaDom(uploadName);
    await page.locator("#tab-notepad").click();
    await waitForTabState("notepad", { focused: true });
    await waitForPageCondition(
      "notepad journey enabled",
      () => {
        const titleInput = document.getElementById("notepadTitleInput");
        const textarea = document.getElementById("notepadTextarea");
        return Boolean(titleInput && textarea && !titleInput.disabled && !textarea.disabled);
      },
      null,
      15000
    );
    await switchLanguage("ru");
    await assertNotepadAccessibilityContracts({
      expectedWarningTokens: [
        "перезагрузки страницы",
        "перезапуска браузера или сервера",
        "TTL сессии",
        "LRU-вытеснения",
        "Ключ восстановления не хранится",
      ],
      expectedLabelText: "Текст заметки",
      expectedDetailsTokens: [
        "зашифрованный текст",
        "метаданные",
        "не AES-ключ",
        "не является резервной копией",
      ],
    });

    const noteTitle = "Browser Smoke Mode Note";
    const noteText = "browser smoke isolated notepad body";
    await createAutosavedNote(noteTitle, noteText);
    await page.locator("#notepadNewBtn").click();
    await loadNoteByKeyboard(noteTitle);
    const loadedTitle = await page.locator("#notepadTitleInput").inputValue();
    const loadedText = await page.locator("#notepadTextarea").inputValue();
    if (loadedTitle !== noteTitle || loadedText !== noteText) {
      throw new Error(
        `Isolated Notepad load mismatch: title=${loadedTitle}; text=${loadedText}`
      );
    }
    await assertNotepadDestructiveMethodStates();
    await assertNotepadSaveErrorSurfacesDetail(noteText);
    const dirtyTransition = await assertDirtyTransitionFlushes();
    const staleLoadGuard = await assertStaleLoadDoesNotOverwriteDirtyDraft();
    const wsLostAckRetry = await assertWsLostAckRetryIsIdempotent();

    await installNotepadWsActionRecorder();
    let wsCoverage;
    let notesClearPreservedUpload;
    const selectiveDeleteTitle = "Browser Smoke Mode Delete";
    try {
      // Reconnect after installing the recorder so the active NOTE socket is wrapped.
      await page.locator('input[name="notepadTransport"][value="http"]').check();
      await waitForConnectionStatus("connected", "http", 15000);
      await page.locator('input[name="notepadTransport"][value="ws"]').check();
      await waitForConnectionStatus("connected", "ws", 15000);

      const wsNoteTitle = "Browser Smoke Mode WS Note";
      const wsNoteText = "browser smoke isolated websocket body";
      await createAutosavedNote(wsNoteTitle, wsNoteText);
      await page.locator("#notepadNewBtn").click();
      await loadNoteByKeyboard(wsNoteTitle);
      const wsLoadedTitle = await page.locator("#notepadTitleInput").inputValue();
      const wsLoadedText = await page.locator("#notepadTextarea").inputValue();
      if (wsLoadedTitle !== wsNoteTitle || wsLoadedText !== wsNoteText) {
        throw new Error(
          `Isolated WS Notepad load mismatch: title=${wsLoadedTitle}; text=${wsLoadedText}`
        );
      }

      const selectiveKeepTitle = "Browser Smoke Mode Keep";
      await createAutosavedNote(selectiveKeepTitle, "keep this isolated note");
      await createAutosavedNote(selectiveDeleteTitle, "delete this isolated note");
      await deleteSelectedNoteViaUiAndAssert(selectiveDeleteTitle, selectiveKeepTitle);
      notesClearPreservedUpload = await clearNotesViaUiAndAssert(uploadPathToPreserve);
      wsCoverage = await assertNotepadWsActionCoverage();
    } finally {
      await page.evaluate(() => {
        if (typeof window.__xferryRestoreNotepadWsActionRecorder === "function") {
          window.__xferryRestoreNotepadWsActionRecorder();
        }
      });
    }
    await deleteSelectedUploadViaUiAndAssert(uploadPathToPreserve);

    return {
      loadedTitle,
      loadedText,
      dirtyTransition,
      staleLoadGuard,
      wsLostAckRetry,
      selectedNoteDeleted: selectiveDeleteTitle,
      notesClearPreservedUpload,
      wsCoverage,
    };
  }

  async function runMobileJourney() {
    const startedAt = Date.now();
    await page.setViewportSize({ width: 390, height: 844 });
    const uploadName = uploadFilePath.split(/[\\/]/).pop();
    await uploadViaDom(uploadName);
    await browseUploadsAndAssert(uploadName);
    const smuggleMobileLayout = await assertSmuggleMobileLayoutContract(uploadName);
    await fetchViaServerFilesAndAssert(uploadName);
    const mobileLayout = await assertMobileLayoutSnapshot();
    await browseUploadsAndAssert(uploadName);
    await deleteViaServerFilesAndAssert(uploadName);
    const durationMs = Date.now() - startedAt;
    if (durationMs >= 300000) {
      throw new Error(`Mobile first-run exceeded five minutes: ${durationMs}ms`);
    }
    return {
      uploadedFile: uploadName,
      downloadedFile: uploadName,
      deletedFile: uploadName,
      durationMs,
      mobileLayout,
      smuggleMobileLayout,
    };
  }

  async function runHappyPath() {
    await assertOutputLiveRegionContracts();
    await assertStaticUiAssetsLoaded();
    await assertVisibleAppVersion();
    await waitForAdvancedUploadReady();
    await assertTopTabContract({ lang: "ru", viewportLabel: "desktop", expectedActive: "upload" });
    await assertDirectHashTabRoutes();
    await page.goto(rootUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForAdvancedUploadReady();
    await assertUnsupportedStoredLanguageFallsBack();
    await waitForAdvancedUploadReady();
    const headerStateControls = await assertHeaderStateControls();
    const reducedMotion = await assertReducedMotionAndTextlessDisclosures();
    await assertTopTabContract({
      lang: "ru",
      viewportLabel: "desktop fresh reload",
      expectedActive: "upload",
      verifyFocusOrder: false,
    });
    await assertRequestPreviewStorageContract();
    await assertHomeToolEntryState(["upload", "files", "request", "opsec", "notepad"]);
    await assertHeroResponsePanelState("idle");
    await waitForTabState("request");
    const requestPanelFetchPath = await fetchViaRequestPanelAndAssert();
    await assertHeroResponsePanelState("active");
    await page.locator("#tab-upload").click();
    await waitForTabState("upload", { focused: true });
    await assertUploadHelpUx();

    await waitForUploadMethodState("POST");
    await page.locator('[data-upload-method="POST"]').focus();
    await page.keyboard.press("ArrowRight");
    await waitForUploadMethodState("NONE", { focused: true });
    await page.keyboard.press("ArrowLeft");
    await waitForUploadMethodState("POST", { focused: true });
    await page.keyboard.press("End");
    await waitForUploadMethodState("PATCH", { focused: true });
    await page.keyboard.press("Home");
    await waitForUploadMethodState("POST", { focused: true });

    const uploadName = uploadFilePath.split(/[\\/]/).pop();
    await uploadViaDom(uploadName);

    await page.locator("#tab-request").click();
    await waitForTabState("request", { focused: true });
    const requestPanelSmugglePopupUrl = await smuggleViaRequestPanelAndAssert(uploadName);

    await browseUploadsAndAssert(uploadName);
    await waitForLiveRegionText("filesResponseAreaLive", "INFO /uploads 200 OK", 10000);
    await assertFileActionAccessibleNames(uploadName);
    await fetchViaServerFilesAndAssert(uploadName);
    await assertSmuggleSearchableComboboxContract(uploadName);
    await assertSmuggleDialogKeyboardContract(uploadName);
    const smugglePopupUrl = await smuggleViaServerFilesAndAssert(uploadName);
    const xorSmuggle = await smuggleViaModalAndAssert(uploadName, "xor");
    const infoPath = await infoViaServerFilesAndAssert(uploadName);
    await browseUploadsAndAssert(uploadName);
    await assertDeleteDialogKeyboardContract(uploadName);
    await deleteViaServerFilesAndAssert(uploadName);
    await assertOpsecQuickFlowUx();
    await assertOpsecPasswordValidationAccessibility(opsecUploadFilePath);
    const opsecMethodConsistency = await uploadOpsecViaUiAndAssertMethodStable(opsecUploadFilePath);

    await page.locator("#tab-notepad").click();
    await waitForTabState("notepad", { focused: true });
    await waitForPageCondition("notepad enabled", () => {
      const titleInput = document.getElementById("notepadTitleInput");
      const textarea = document.getElementById("notepadTextarea");
      return Boolean(titleInput && textarea && !titleInput.disabled && !textarea.disabled);
    }, null, 15000);

    await switchLanguage("ru");
    await assertLocaleSnapshot({
      uploadTabText: "Отправить",
      filesTabText: "Файлы",
      requestTabText: "Запросы",
      opsecTabText: "Расширенные",
      notepadTabText: "Блокнот",
      brandTaglineText: "Инструмент для тестирования SWG",
      heroTitleText: "Проверяйте HTTP-пути передачи данных",
      mismatchLabelText: "Не работает",
      smuggleActionLabelText: "HTML Smuggling",
      noteListText: "Нет заметок",
      charCountText: "0 симв.",
      themeLabel: "Тёмная тема включена. Переключить на светлую",
      notepadTitleMetadataHintText: "Заголовок видим серверу как метаданные.",
      notepadEphemeralWarningText: "Сохранённый текст может стать нерасшифровываемым",
      notepadTextareaLabelText: "Текст заметки",
    });
    await assertNotepadAccessibilityContracts({
      expectedWarningTokens: [
        "перезагрузки страницы",
        "перезапуска браузера или сервера",
        "TTL сессии",
        "LRU-вытеснения",
        "Ключ восстановления не хранится",
      ],
      expectedLabelText: "Текст заметки",
      expectedDetailsTokens: [
        "зашифрованный текст",
        "метаданные",
        "не AES-ключ",
        "не является резервной копией",
      ],
    });
    await switchLanguage("en");
    await assertLocaleSnapshot({
      uploadTabText: "Send",
      filesTabText: "Files",
      requestTabText: "Requests",
      opsecTabText: "Advanced",
      notepadTabText: "Notepad",
      brandTaglineText: "SWG testing tool",
      heroTitleText: "Test HTTP data-transfer paths",
      mismatchLabelText: "Mismatches",
      smuggleActionLabelText: "HTML smuggling",
      forbiddenText: "Doesn't work",
      noteListText: "No notes",
      charCountText: "0 chars",
      themeLabel: "Dark theme is active. Switch to light theme",
      notepadTitleMetadataHintText: "The title is server-visible metadata.",
      notepadEphemeralWarningText: "Saved note text can become undecryptable",
      notepadTextareaLabelText: "Note text",
    });
    await assertNotepadAccessibilityContracts({
      expectedWarningTokens: [
        "page reload",
        "browser or server restart",
        "session TTL expiry",
        "LRU eviction",
        "No recovery key is stored",
      ],
      expectedLabelText: "Note text",
      expectedDetailsTokens: [
        "encrypted text",
        "metadata",
        "not the AES key",
        "not a backup",
      ],
    });
    await switchLanguage("ru");
    await assertLocaleSnapshot({
      uploadTabText: "Отправить",
      filesTabText: "Файлы",
      requestTabText: "Запросы",
      opsecTabText: "Расширенные",
      notepadTabText: "Блокнот",
      brandTaglineText: "Инструмент для тестирования SWG",
      heroTitleText: "Проверяйте HTTP-пути передачи данных",
      mismatchLabelText: "Не работает",
      smuggleActionLabelText: "HTML Smuggling",
      noteListText: "Нет заметок",
      charCountText: "0 симв.",
      themeLabel: "Тёмная тема включена. Переключить на светлую",
      notepadTitleMetadataHintText: "Заголовок видим серверу как метаданные.",
      notepadEphemeralWarningText: "Сохранённый текст может стать нерасшифровываемым",
      notepadTextareaLabelText: "Текст заметки",
    });
    await assertSharedDialogRoleContract();

    const noteTitle = "Browser Smoke Note";
    const noteText = "browser smoke note body";
    await createAutosavedNote(noteTitle, noteText);
    await switchLanguage("en");
    await waitForText(page.locator("#notepadSaveIndicator"), "Saved", 15000);
    await waitForText(page.locator("#notepadCharCount"), `${noteText.length} chars`, 15000);
    await switchLanguage("ru");
    await waitForText(page.locator("#notepadSaveIndicator"), "Сохранено", 15000);
    await waitForText(page.locator("#notepadCharCount"), `${noteText.length} симв.`, 15000);

    await page.locator("#notepadNewBtn").click();
    await loadNoteByKeyboard(noteTitle);

    const loadedTitle = await page.locator("#notepadTitleInput").inputValue();
    const loadedText = await page.locator("#notepadTextarea").inputValue();
    if (loadedTitle !== noteTitle) {
      throw new Error(`Loaded note title mismatch: ${loadedTitle}`);
    }
    if (loadedText !== noteText) {
      throw new Error(`Loaded note text mismatch: ${loadedText}`);
    }

    await assertNotepadDestructiveMethodStates();
    await assertNotepadSaveErrorSurfacesDetail(noteText);

    await page.locator("#notepadDeleteBtn").click();
    await confirmAppDialog(noteTitle, 10000);
    await waitForPageCondition(
      `notepad note deleted (${noteTitle})`,
      ([targetTitle]) => {
        const titleInput = document.getElementById("notepadTitleInput");
        const textarea = document.getElementById("notepadTextarea");
        const deleteBtn = document.getElementById("notepadDeleteBtn");
        const noteList = document.getElementById("notepadNoteList");
        const titleInputFocused = document.activeElement === titleInput;
        return Boolean(
          titleInput &&
          textarea &&
          deleteBtn &&
          noteList &&
          titleInput.value === "" &&
          textarea.value === "" &&
          deleteBtn.disabled &&
          !noteList.innerText.includes(targetTitle) &&
          titleInputFocused
        );
      },
      [noteTitle],
      15000
    );
    await waitForText(page.locator("#notepadNoteList"), /Нет заметок|No notes/, 15000);

    const dirtyTransition = await assertDirtyTransitionFlushes();
    const staleLoadGuard = await assertStaleLoadDoesNotOverwriteDirtyDraft();

    await page.locator('input[name="notepadTransport"][value="ws"]').check();
    await waitForConnectionStatus("connected", "ws", 15000);

    const wsLostAckRetry = await assertWsLostAckRetryIsIdempotent();

    await installNotepadWsActionRecorder();
    let wsCoverage;
    const wsNoteTitle = "Browser Smoke WS Note";
    const wsNoteText = "browser smoke websocket note body";
    const selectiveDeleteTitle = "Browser Smoke Selective Delete";
    let wsConnClass;
    let wsConnState;
    let wsConnTransport;
    let wsLoadedTitle;
    let wsLoadedText;
    let notesClearPreservedUpload;
    try {
      // Reconnect after installing the recorder so the active NOTE socket is wrapped.
      await page.locator('input[name="notepadTransport"][value="http"]').check();
      await waitForConnectionStatus("connected", "http", 15000);
      await page.locator('input[name="notepadTransport"][value="ws"]').check();
      await waitForConnectionStatus("connected", "ws", 15000);
      await createAutosavedNote(wsNoteTitle, wsNoteText);

      wsConnClass = await page.locator("#notepadConnStatus").evaluate((node) => node.className);
      wsConnState = await page.locator("#notepadConnStatus").getAttribute("data-state");
      wsConnTransport = await page.locator("#notepadConnStatus").getAttribute("data-transport");
      if (!wsConnClass.includes("connected")) {
        throw new Error(`Unexpected connection class after WS switch: ${wsConnClass}`);
      }
      if (wsConnState !== "connected" || wsConnTransport !== "ws") {
        throw new Error(`Unexpected DOM connection contract after WS switch: state=${wsConnState}; transport=${wsConnTransport}`);
      }

      await page.locator("#notepadNewBtn").click();
      await clickNoteByTitle(wsNoteTitle);

      wsLoadedTitle = await page.locator("#notepadTitleInput").inputValue();
      wsLoadedText = await page.locator("#notepadTextarea").inputValue();
      if (wsLoadedTitle !== wsNoteTitle) {
        throw new Error(`WS loaded title mismatch: ${wsLoadedTitle}`);
      }
      if (wsLoadedText !== wsNoteText) {
        throw new Error(`WS loaded text mismatch: ${wsLoadedText}`);
      }

      const selectiveKeepTitle = "Browser Smoke Selective Keep";
      await createAutosavedNote(selectiveKeepTitle, "keep this note");
      await createAutosavedNote(selectiveDeleteTitle, "delete this note");
      await deleteSelectedNoteViaUiAndAssert(selectiveDeleteTitle, selectiveKeepTitle);

      notesClearPreservedUpload = await clearNotesViaUiAndAssert(requestPanelFetchPath);
      wsCoverage = await assertNotepadWsActionCoverage();
    } finally {
      await page.evaluate(() => {
        if (typeof window.__xferryRestoreNotepadWsActionRecorder === "function") {
          window.__xferryRestoreNotepadWsActionRecorder();
        }
      });
    }
    await deleteSelectedUploadViaUiAndAssert(requestPanelFetchPath);

    const mobileLayout = await assertMobileLayoutSnapshot();
    await clearUploadsViaUiAndAssertSummaryPersistence();

    return {
      ping: "pong",
      uploadedFile: uploadName,
      requestPanelFetchPath,
      requestPanelSmugglePopupUrl,
      infoPath,
      smugglePopupUrl,
      xorSmuggle,
      opsecSizePolicy: "warnings-only",
      opsecMethodConsistency,
      headerStateControls,
      reducedMotion,
      loadedTitle,
      loadedText,
      wsLoadedTitle,
      wsLoadedText,
      wsConnState,
      wsConnTransport,
      wsConnClass,
      wsLostAckRetry,
      wsCoverage,
      notesClearPreservedUpload,
      selectedUploadDeleted: requestPanelFetchPath,
      uploadsCleared: true,
      selectedNoteDeleted: selectiveDeleteTitle,
      dirtyTransition,
      staleLoadGuard,
      mobileLayout,
    };
  }

  async function runUnavailablePath() {
    async function waitForUnavailableMessage(expectedText, timeout = 15000) {
      await waitForPageCondition(
        `waitForUnavailableMessage(${expectedText})`,
        ([targetText]) => {
          const indicator = document.getElementById("notepadSaveIndicator");
          return Boolean(
            indicator &&
            indicator.textContent &&
            indicator.textContent.includes(targetText)
          );
        },
        [expectedText],
        timeout
      );
    }

    async function getUnavailableSnapshot() {
        return {
          saveIndicator: (await page.locator("#notepadSaveIndicator").textContent() || "").trim(),
          connTitle: await page.locator("#notepadConnStatus").getAttribute("title") || "",
          connText: (await page.locator("#notepadConnStatusText").textContent() || "").trim(),
          connClass: await page.locator("#notepadConnStatus").evaluate((node) => node.className),
          connState: await page.locator("#notepadConnStatus").getAttribute("data-state") || "",
          connTransport: await page.locator("#notepadConnStatus").getAttribute("data-transport") || "",
        noteListText: (await page.locator("#notepadNoteList").textContent() || "").trim(),
        titleDisabled: await page.locator("#notepadTitleInput").isDisabled(),
        textareaDisabled: await page.locator("#notepadTextarea").isDisabled(),
        transportsDisabled: await page.locator('input[name="notepadTransport"][value="http"]').isDisabled() &&
          await page.locator('input[name="notepadTransport"][value="ws"]').isDisabled(),
      };
    }

    function assertUnavailableSnapshot(snapshot, expectedUnavailable, localeLabel) {
      if (snapshot.saveIndicator !== expectedUnavailable) {
        throw new Error(`[${localeLabel}] Unexpected unavailable status text: ${snapshot.saveIndicator}`);
      }
      if (!snapshot.connClass.includes("disconnected")) {
        throw new Error(`[${localeLabel}] Unexpected unavailable connection class: ${snapshot.connClass}`);
      }
      if (snapshot.connState !== "disconnected") {
        throw new Error(`[${localeLabel}] Unexpected unavailable connection state: ${snapshot.connState}`);
      }
      if (snapshot.connTransport !== "http") {
        throw new Error(`[${localeLabel}] Unexpected unavailable connection transport: ${snapshot.connTransport}`);
      }
      if (snapshot.connTitle !== expectedUnavailable) {
        throw new Error(`[${localeLabel}] Unexpected unavailable connection tooltip: ${snapshot.connTitle}`);
      }
      if (snapshot.connText !== expectedUnavailable) {
        throw new Error(`[${localeLabel}] Unexpected unavailable connection live text: ${snapshot.connText}`);
      }
      if (snapshot.noteListText !== expectedUnavailable) {
        throw new Error(`[${localeLabel}] Unexpected unavailable note list text: ${snapshot.noteListText}`);
      }
      if (!snapshot.titleDisabled || !snapshot.textareaDisabled || !snapshot.transportsDisabled) {
        throw new Error(`[${localeLabel}] Notepad controls were not disabled in unavailable mode`);
      }
    }

    const expectedUnavailableRu =
      "Блокнот недоступен: восстановите или переустановите стандартные зависимости времени выполнения сервера.";
    const expectedUnavailableEn =
      "Notepad unavailable: repair or reinstall the server default runtime dependencies.";

    await switchLanguage("ru");
    await page.locator("#tab-opsec").click();
    await waitForTabState("opsec", { focused: true });
    await waitForAdvancedUploadReady();
    await page.locator("#tab-notepad").click();
    await waitForUnavailableMessage(expectedUnavailableRu);
    const ruSnapshot = await getUnavailableSnapshot();
    assertUnavailableSnapshot(ruSnapshot, expectedUnavailableRu, "ru");

    await switchLanguage("en");
    await waitForUnavailableMessage(expectedUnavailableEn);
    const enSnapshot = await getUnavailableSnapshot();
    assertUnavailableSnapshot(enSnapshot, expectedUnavailableEn, "en");

    return {
      ru: ruSnapshot,
      en: enSnapshot,
    };
  }

  const namedJourneys = {
    "first-run": runFirstRunJourney,
    "basic-upload-profiles": runBasicUploadProfilesJourney,
    "ui-contracts": runUiContractsJourney,
    "http-errors": runHttpErrorsJourney,
    "recovery": runRecoveryJourney,
    "request-matrix": runRequestMatrixJourney,
    "advanced": runAdvancedJourney,
    "advanced-constructor-profiles": runAdvancedConstructorProfilesJourney,
    "advanced-session": runAdvancedSessionJourney,
    "files": runFilesJourney,
    "smuggle": runSmuggleJourney,
    "notepad": runNotepadJourney,
    "mobile": runMobileJourney,
  };

  async function runNamedJourney(name) {
    const journey = namedJourneys[name];
    if (!journey) {
      throw new Error(`Unsupported browser smoke mode: ${name}`);
    }
    try {
      const result = await journey();
      await assertNoBrowserIssues(name);
      return {
        journey: name,
        ...result,
      };
    } catch (error) {
      throw new Error(`[${name}] ${error.message}`);
    }
  }

  async function executeBrowserSmoke() {
    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await installClipboardMock();
    await waitForAdvancedUploadReady();

    if (smokeMode !== "full") {
      const result = await runNamedJourney(smokeMode);
      if (smokeMode !== "notepad" || !unavailableUrl) {
        return result;
      }
      const unavailableIssueCheckpoint = browserIssues.length;
      await page.goto(unavailableUrl, { waitUntil: "domcontentloaded" });
      await waitForSpaReady();
      await waitForAdvancedUploadReady();
      const unavailablePath = await runUnavailablePath();
      await assertNoBrowserIssues("notepad unavailable path", {
        since: unavailableIssueCheckpoint,
        expectedUnavailableNotepadUrl: `${String(unavailableUrl).replace(/\/+$/, "")}/notes/key`,
      });
      return {
        ...result,
        unavailablePath,
      };
    }

    const happyPath = await runHappyPath();
    await assertNoBrowserIssues("full happy path");
    const aggregateJourneys = Object.keys(namedJourneys);
    if (!unavailableUrl) {
      return {
        journey: "full",
        aggregateJourneys,
        happyPath,
      };
    }

    const unavailableIssueCheckpoint = browserIssues.length;
    await page.goto(unavailableUrl, { waitUntil: "domcontentloaded" });
    await waitForSpaReady();
    await waitForAdvancedUploadReady();
    const unavailablePath = await runUnavailablePath();
    await assertNoBrowserIssues("full unavailable path", {
      since: unavailableIssueCheckpoint,
      expectedUnavailableNotepadUrl: `${String(unavailableUrl).replace(/\/+$/, "")}/notes/key`,
    });
    return {
      journey: "full",
      aggregateJourneys,
      happyPath,
      unavailablePath,
    };
  }

  try {
    return await executeBrowserSmoke();
  } catch (error) {
    if (artifactDir) {
      const normalizedArtifactDir = String(artifactDir).replace(/[\\/]+$/, "");
      try {
        await page.screenshot({
          path: `${normalizedArtifactDir}/${smokeMode}-failure.png`,
          fullPage: true,
        });
      } catch (screenshotError) {
        // Keep the original journey failure authoritative.
      }
    }
    throw new Error(`[${smokeMode}] ${error.message}`);
  }
}
