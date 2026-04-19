export interface User {
  id: string;
  username: string;
  avatar?: string;

  access_token?: Uint8Array<ArrayBuffer>;
  access_token_iv?: Uint8Array<ArrayBuffer>;
  refresh_token?: Uint8Array<ArrayBuffer>;
  refresh_token_iv?: Uint8Array<ArrayBuffer>;
  expires_at?: number;

  banned?: boolean;
}
