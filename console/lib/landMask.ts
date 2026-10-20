// Compact equirectangular land/sea mask (180×90, 2° per cell), bit-packed MSB-first
// row-major (land = 1), base64-encoded. ~2 KB. Derived once at authoring time from a
// public-domain equirectangular world image and embedded here, so the runtime stays
// fully self-contained (no fetch, no runtime dependency, no named source). Used to
// place the globe's dots on the actual continents.

export const LAND_W = 180;
export const LAND_H = 90;

const LAND_B64 =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH/h///gAAAAAAAAAAAAAAAAAAAAAAAf8H///wAA6AAAAAAAAAAAAAAAAAAwADwf///wAAAAAAAAAPAAAAAAAAAABPgIAAf//wAAAAACAAf/4AEAAAAAAAH+334AP//gAAAAAMBD///+DAAAABgACfx3/AP//gAAA4AMD///////wAAP////59/wH/4AAAP/gH//////////8f//////n+H/AAAAf/7///////////M///////n8D4A+AA+/f///////////Af/////5k4B4AAAD5/////////////A//////gHgAwAAAP7///////////PwAHgH///gH2AAAAAH4/////////+CMAADAD///8D+AAAAGCx/////////8A8AAAAB////n/gAAAPDj/////////wA4AAAAAf///v/wAAAbv///////////AwAAAAAP/////wAAAD////////////AAAAAAAH////4YAAAD///////////9AAAAAAAD//9/8IAAAD///////////4AAAAAAAD////+AAAAB//5ff//////xAAAAAAAD//9/gAAAAPxvwPP//////jAAAAAAAD////AAAAAfib//v/////+CAAAAAAAD///+AAAAAfALf/n/////sCAAAAAAAB///8AAAAAOeRP///////mOAAAAAAAB///8AAAAAH/AA///////G8AAAAAAAAf//4AAAAAf/jB///////hgAAAAAAAAP//gAAAAAf/7////////gAAAAAAAAAP/owAAAAA/////f/////gAAAAAAAAAF/AQAAAAB///+/v/////AAAAAAAAAAC+AAAAAAD////f2X////AAAAAAAAAAAeA4AAAAD////f/D///8gAAAAAAAAAAfGMAAAAH////v/B/z/wAAAAAAAAAAAPsBgAAAD////v+A/h+gAAAAAAAAAAAD8AAAAAD////38A+B/AgAAAAAAAAAAAfAAAAAH/////wAcAfggAAAAAAAAAAADAAAAAH////+AAcAfgQAAAAAAAAAAABDwAAAD////9wAMATAYAAAAAAAAAAAA//AAAB/////wAOASAYAAAAAAAAAAAAH/gAAA/////gACAIAIAAAAAAAAAAAAH/8AAAfH///AAAAsGAAAAAAAAAAAAAH/+AAAAB///AAAA8OAAAAAAAAAAAAAP//AAAAB//8AAAAc+AAAAAAAAAAAAAP//gAAAD/94AAAAOeggAAAAAAAAAAAP//8AAAB//wAAAAGdg+AAAAAAAAAAAf///AAAA//wAAAACAAPgAAAAAAAAAAP///gAAA//wAAAAB4AHwAAAAAAAAAAH///gAAA//wAAAAAAIDYAAAAAAAAAAH///AAAAf/wAAAAAAAAAAAAAAAAAAAD//+AAAA//wgAAAAABxAAAAAAAAAAAD//+AAAA//xgAAAAAPxgAAAAAAAAAAA//+AAAA//zgAAAAAf/gAAAAAAAAAAAf/8AAAA//DgAAAAA//wAAAAAAAAAAAf/8AAAAf/DAAAAAD//4AAAAAAAAAAAf/4AAAAf/DAAAAAH//8AAAAAAAAAAAf/AAAAAf+DAAAAAH//8AAAAAAAAAAA//AAAAAf8AAAAAAH//+AAAAAAAAAAA/+AAAAAP8AAAAAAH//+AAAAAAAAAAA/+AAAAAH4AAAAAAD//+AAAAAAAAAAA/8AAAAAHwAAAAAAD4f8AAAAAAAAAAA/4AAAAAAAAAAAAACAP4AAAAAAAAAAB/wAAAAAAAAAAAAAAAD4AEAAAAAAAAB/AAAAAAAAAAAAAAAAAAAGAAAAAAAAB+AAAAAAAAAAAAAAAAAQAMAAAAAAAAB8AAAAAAAAAAAAAAAAAQAYAAAAAAAAB4AAAAAAAAAAAAAAAAAAAwAAAAAAAAB4AAAAAAAAAAAAAAAAAAAAAAAAAAAAB4AAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAcAAagAHmAAAAAAAAAAAAPAAAAAAAAD/+H/yBf/8AAAAAAAAAAB/AAAAf/P//////yD///zAAAAAAAHuB/AAAP////f//////////AAAAD/4H///AAA///////////////4AAAH///////wAB///////////////wA+P/wP///9+EW5/////////////////n+f//////gAYAv//////////////n/AAD8A////gDg////////////////gAAAAAD///8AH/////////////////4A////////+H//////////////////////////////////////////////////";

let decoded: Uint8Array | null = null;
function bits(): Uint8Array {
  if (decoded) return decoded;
  let bin: string;
  if (typeof atob === "function") bin = atob(LAND_B64);
  else bin = Buffer.from(LAND_B64, "base64").toString("binary");
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  decoded = u;
  return u;
}

/** Is (lat ∈ [-90,90], lon ∈ [-180,180]) over land? */
export function isLand(lat: number, lon: number): boolean {
  const b = bits();
  let x = Math.floor(((lon + 180) / 360) * LAND_W);
  let y = Math.floor(((90 - lat) / 180) * LAND_H);
  if (x < 0) x = 0; else if (x >= LAND_W) x = LAND_W - 1;
  if (y < 0) y = 0; else if (y >= LAND_H) y = LAND_H - 1;
  const i = y * LAND_W + x;
  return (b[i >> 3] & (1 << (7 - (i & 7)))) !== 0;
}
