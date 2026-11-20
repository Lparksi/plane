/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { SOURCE_CODE_URL } from "@plane/constants";

import { observer } from "mobx-react";
import { ProjectsOutline } from "@makeplane/propel/icons";
// components
import { ProjectLogo } from "@/components/common/project-logo";
// store
import type { PublishStore } from "@/store/publish/publish.store";
// local imports
import { NavbarControls } from "./controls";

type Props = {
  publishSettings: PublishStore;
};

export const IssuesNavbarRoot = observer(function IssuesNavbarRoot(props: Props) {
  const { publishSettings } = props;
  // hooks
  const { project_details } = publishSettings;

  return (
    <div className="relative flex w-full flex-wrap items-center justify-between gap-4 px-5">
      {/* project detail */}
      <div className="flex min-w-0 items-center gap-2">
        {project_details ? (
          <span className="grid size-7 shrink-0 place-items-center">
            <ProjectLogo logo={project_details.logo_props} className="text-body-md-regular" />
          </span>
        ) : (
          <span className="grid size-7 shrink-0 place-items-center rounded-sm uppercase">
            <ProjectsOutline className="size-4" />
          </span>
        )}
        <div className="line-clamp-1 max-w-[300px] overflow-hidden text-body-md-medium">
          {project_details?.name || `...`}
        </div>
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        {SOURCE_CODE_URL ? (
          <a className="text-sm underline" href={SOURCE_CODE_URL} target="_blank" rel="noopener noreferrer">
            Source code / 源代码
          </a>
        ) : (
          <span className="text-sm">Source unavailable / 源代码未配置</span>
        )}
        <NavbarControls publishSettings={publishSettings} />
      </div>
    </div>
  );
});
