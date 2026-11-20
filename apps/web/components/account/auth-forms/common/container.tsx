/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { SOURCE_CODE_URL } from "@plane/constants";

export function FormContainer({ children }: { children: React.ReactNode }) {
  return (
    <div className="mt-10 flex w-full flex-grow flex-col items-center justify-center py-6">
      <div className="relative flex w-full max-w-[22.5rem] flex-col gap-6">
        {children}
        {SOURCE_CODE_URL ? (
          <a className="text-sm underline" href={SOURCE_CODE_URL} target="_blank" rel="noopener noreferrer">
            Source code / 源代码
          </a>
        ) : (
          <span className="text-sm">Source unavailable / 源代码未配置</span>
        )}
      </div>
    </div>
  );
}
