/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import React, { useState } from "react";
import { observer } from "mobx-react";
import { HelpOutline, PagesOutline, UserAltOutline } from "@makeplane/propel/icons";
import { SOURCE_CODE_URL, TALK_TO_SALES_URL } from "@plane/constants";
import { useTranslation } from "@plane/i18n";
// ui
import { Icon } from "@makeplane/propel/components/icon";
import { Menu, MenuContent, MenuFooter, MenuItem, MenuSeparator, MenuTrigger } from "@makeplane/propel/components/menu";
import { Tooltip } from "@makeplane/propel/components/tooltip";
import { IconButton } from "@makeplane/propel/elements/icon-button";
// components
import { ProductUpdatesModal } from "@/components/global";
import { PlaneVersionNumber } from "@/components/global/version-number";
// hooks
import { usePowerK } from "@/hooks/store/use-power-k";

export const HelpMenuRoot = observer(function HelpMenuRoot() {
  // store hooks
  const { t } = useTranslation();
  const { toggleShortcutsListModal } = usePowerK();
  // states
  const [isProductUpdatesModalOpen, setProductUpdatesModalOpen] = useState(false);

  return (
    <>
      <ProductUpdatesModal isOpen={isProductUpdatesModalOpen} handleClose={() => setProductUpdatesModalOpen(false)} />

      <Menu>
        <Tooltip label={t("power_k.group_titles.help")} side="bottom">
          <MenuTrigger
            render={
              <IconButton
                variant="ghost"
                size="md"
                aria-label={t("power_k.group_titles.help")}
                render={<button type="button" className="data-popup-open:bg-layer-transparent-active" />}
              >
                <HelpOutline className="size-4.5" />
              </IconButton>
            }
          />
        </Tooltip>
        <MenuContent
          side="bottom"
          align="end"
          footer={
            <MenuFooter>
              <PlaneVersionNumber />
              {!SOURCE_CODE_URL && <span>Source unavailable / 源代码未配置</span>}
            </MenuFooter>
          }
        >
          <MenuItem
            icon={<Icon icon={PagesOutline} tint="secondary" />}
            label={t("documentation")}
            onClick={() => window.open("https://go.plane.so/p-docs", "_blank")}
          />
          {SOURCE_CODE_URL && (
            <MenuItem
              label="Source code / 源代码"
              onClick={() => window.open(SOURCE_CODE_URL, "_blank", "noopener,noreferrer")}
            />
          )}
          <MenuItem
            icon={<Icon icon={UserAltOutline} tint="secondary" />}
            label={t("contact_sales")}
            onClick={() => window.open(TALK_TO_SALES_URL, "_blank", "noopener,noreferrer")}
          />
          <MenuSeparator />
          <MenuItem label={t("keyboard_shortcuts")} onClick={() => toggleShortcutsListModal(true)} />
          <MenuItem label={t("whats_new")} onClick={() => setProductUpdatesModalOpen(true)} />
          <MenuItem
            label="Forum"
            onClick={() => window.open("https://forum.plane.so", "_blank", "noopener,noreferrer")}
          />
        </MenuContent>
      </Menu>
    </>
  );
});
