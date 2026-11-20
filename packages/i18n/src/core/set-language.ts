/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { initPromise, i18nInstance } from "./instance";
import { FALLBACK_LANGUAGE, LANGUAGE_STORAGE_KEY, toSupportedLanguage } from "../constants/language";
import type { TLanguage } from "../types";

let instanceLanguage: TLanguage = FALLBACK_LANGUAGE;
let profileLanguage: TLanguage | undefined;
let languageUpdate = 0;

async function applyLanguage(): Promise<void> {
  if (typeof window === "undefined") return;
  const update = ++languageUpdate;
  const language = profileLanguage ?? instanceLanguage;
  await initPromise;
  if (update !== languageUpdate) return;
  if (i18nInstance.language !== language) await i18nInstance.changeLanguage(language);
  if (update !== languageUpdate) return;
  document.documentElement.lang = language;
  try {
    if (profileLanguage) localStorage.setItem(LANGUAGE_STORAGE_KEY, profileLanguage);
    else localStorage.removeItem(LANGUAGE_STORAGE_KEY);
  } catch {
    // Rendering the requested language does not depend on browser storage.
  }
}

export function setLanguage(lng: TLanguage): Promise<void> {
  profileLanguage = toSupportedLanguage(lng);
  return applyLanguage();
}

export function setInstanceLanguage(lng?: string): Promise<void> {
  instanceLanguage = toSupportedLanguage(lng) ?? FALLBACK_LANGUAGE;
  return applyLanguage();
}

export function clearProfileLanguage(): Promise<void> {
  profileLanguage = undefined;
  return applyLanguage();
}
