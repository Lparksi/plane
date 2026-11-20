/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useTranslation } from "@plane/i18n";
import { ContentWrapper } from "@plane/blocks/layout";

export function WorkspaceActiveCyclesUpgrade() {
  const { t } = useTranslation();
  return (
    <ContentWrapper>
      <div className="space-y-2 py-6">
        <h1 className="text-h4-semibold">{t("active_cycles")}</h1>
        <p className="text-body-sm-regular text-tertiary">{t("feature_unavailable_community")}</p>
      </div>
    </ContentWrapper>
  );
}
