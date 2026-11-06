// Produces tests/golden/fixtures.json: exact execute() calldata from the official SDK.
// The SDK is driven through a recording transport, so nothing leaves the machine.
import { writeFileSync } from "node:fs";
import { custom } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createWalletClient } from "@arkiv-network/sdk";
import { defineSchema, str, u64, u256, dec, i32, bool, addr, key, bytes } from "@arkiv-network/sdk/schema";
import { ExpirationTime } from "@arkiv-network/sdk";

// Public Hardhat key 0, never a real one.
const account = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const chain = { id: 7794095, name: "rabdi", nativeCurrency: { name: "E", symbol: "E", decimals: 18 }, rpcUrls: { default: { http: ["http://x"] } } };

let captured;
const transport = custom({
  async request({ method, params }) {
    if (method === "eth_blockNumber") return "0x64";
    if (method === "eth_estimateGas") { captured = params[0].data; return "0x30d40"; }
    if (method === "eth_getBlockByNumber") return { baseFeePerGas: "0x1", number: "0x64", timestamp: "0x1" };
    if (method === "eth_maxPriorityFeePerGas") return "0x1";
    if (method === "eth_gasPrice") return "0x1";
    if (method === "eth_getTransactionCount") return "0x0";
    if (method === "eth_chainId") return "0x76f1af";
    if (method === "eth_sendRawTransaction") { throw new Error("STOP"); }
    throw new Error("unexpected " + method);
  },
});
const wallet = createWalletClient({ chain, transport, account });

const owner = "0x0f05df479fcb23b2281e28813fb47e57e47d1bb7";
const refKey = "0x59c5ddf06b5605e27833d0a02c8f6e96cebf9f334a6470b39e31eccb34895807";
const salt = (n) => BigInt("0x0102030405060708090a0b0c0d0e0f10") + BigInt(n);

// Each entity: {schema, flags, expiry, salt, attrs:[{name,type,indexed,value}]} (value as JSON)
const all = [
  { name: "text", type: "str", indexed: true, value: "hello é world" },
  { name: "strPlain", type: "str", indexed: false, value: "x".repeat(70) },
  { name: "empty", type: "str", indexed: false, value: "" },
  { name: "count", type: "u64", indexed: true, value: "42" },
  { name: "big", type: "u64", indexed: false, value: "18446744073709551615" },
  { name: "wide", type: "u256", indexed: true, value: "115792089237316195423570985008687907853269984665640564039457584007913129639935" },
  { name: "neg", type: "i32", indexed: true, value: -7 },
  { name: "negMin", type: "i32", indexed: false, value: -2147483648 },
  { name: "flag", type: "bool", indexed: true, value: true },
  { name: "off", type: "bool", indexed: false, value: false },
  { name: "price", type: "dec", indexed: true, value: "1.5" },
  { name: "loss", type: "dec", indexed: false, value: "-0.000000000000000001" },
  { name: "wallet", type: "addr", indexed: true, value: owner },
  { name: "ref", type: "key", indexed: true, value: refKey },
  { name: "blob", type: "bytes", indexed: false, value: "0xdeadbeef" },
  { name: "blobBig", type: "bytes", indexed: false, value: "0x" + "ab".repeat(100) },
];
const ents = [
  { schema: "golden.all", flags: { readonly: false }, expiry: { minLifetime: 7800000 }, salt: salt(0), attrs: all },
  { schema: "golden.all", flags: { readonly: true }, expiry: { minLifetime: 7800000 }, salt: salt(1), attrs: all },
  { schema: "golden.ext", flags: { readonly: false, permissionlessExtension: true }, expiry: { minLifetime: 1 }, salt: salt(2), attrs: [all[3]] },
  { schema: "golden.max", flags: { readonly: true }, expiry: { minLifetime: 7884000 }, salt: salt(3), attrs: [all[0], all[10]] },
  { schema: "golden.abs", flags: {}, expiry: { atBlock: 5000000 }, salt: salt(4), attrs: [all[12]] },
  { schema: "golden.zero", flags: {}, expiry: { minLifetime: 43200 }, salt: 0, attrs: [all[8]] },
];

const ctor = { str, u64, u256, dec, i32, bool, addr, key, bytes };
const val = (a) => {
  const v = a.type === "u64" || a.type === "u256" ? BigInt(a.value) : a.value;
  return ctor[a.type](v);
};
const makeCreate = (e) => {
  const cols = {};
  for (const a of e.attrs) { const c = ctor[a.type](); cols[a.name] = a.indexed ? c.indexed() : c; }
  const schema = defineSchema(e.schema, cols);
  const values = {};
  for (const a of e.attrs) values[a.name] = val(a);
  const expiration = e.expiry.atBlock !== undefined ? ExpirationTime.atBlock(BigInt(e.expiry.atBlock)) : { minLifetime: BigInt(e.expiry.minLifetime), expiresAt: 0n };
  return { schema, values, expiration, salt: BigInt(e.salt), flags: e.flags };
};

async function calldata(list) {
  captured = undefined;
  try { await wallet.executeBatch({ creates: list.map(makeCreate) }); } catch (e) { if (!String(e).includes("STOP") && !captured) throw e; }
  if (!captured) throw new Error("no calldata captured");
  return captured;
}

const cases = [];
for (const [i, e] of ents.entries()) {
  cases.push({ id: `single_${i}`, entities: [e].map(ser), calldata: await calldata([e]) });
}
cases.push({ id: "batch_all", entities: ents.map(ser), calldata: await calldata(ents) });
cases.push({ id: "batch_pair", entities: [ents[1], ents[3]].map(ser), calldata: await calldata([ents[1], ents[3]]) });

function ser(e) {
  return { ...e, salt: "0x" + BigInt(e.salt).toString(16), expiry: e.expiry.atBlock !== undefined ? { expiresAt: e.expiry.atBlock, minLifetime: 0 } : { expiresAt: 0, minLifetime: e.expiry.minLifetime },
    readonly: !!e.flags.readonly, permissionlessExtension: !!e.flags.permissionlessExtension };
}
for (const c of cases) c.entities = c.entities.map(({ flags, ...r }) => r);
writeFileSync(new URL("./fixtures.json", import.meta.url), JSON.stringify(cases, null, 1));
console.log("wrote", cases.length, "cases");
