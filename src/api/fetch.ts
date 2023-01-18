import { AxiosRequestConfig } from "axios";

export let globalConfig: Partial<AxiosRequestConfig> = {};

export function setGlobalConfig(config: Partial<AxiosRequestConfig>) {
    globalConfig = config;
}
