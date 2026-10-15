import { createContext, useContext } from 'react';

export const UiCtx = createContext({ openIP: () => {}, closeIP: () => {} });
export const useUi = () => useContext(UiCtx);
