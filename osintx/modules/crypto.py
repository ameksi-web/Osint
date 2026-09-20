"""Криптоадреса: баланс, транзакции, связь с биржами (реальные данные блокчейнов).

Источники без ключей:
  * Blockstream.info API — Bitcoin (баланс, число транзакций, последние транзакции);
  * Blockchair — Bitcoin и Ethereum (баланс, счётчики, цена);
  * Ethplorer (freekey) — токены и история ETH-адреса.
"""
from __future__ import annotations

from ..core.models import ModuleResult, SourceStatus
from ..core.utils import BTC_RE, ETH_RE
from .base import Context, Module, add_entity


class CryptoModule(Module):
    name = "crypto"
    title = "Криптоадрес: баланс, транзакции, активность (Bitcoin/Ethereum)"
    categories = ("crypto",)
    target_types = ("crypto",)

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        address = target.strip()
        is_btc, is_eth = bool(BTC_RE.match(address)), bool(ETH_RE.match(address))
        if not (is_btc or is_eth):
            result.errors.append("Адрес не распознан как Bitcoin или Ethereum")
            return
        add_entity(result, "crypto", address, chain="bitcoin" if is_btc else "ethereum")
        if is_btc:
            await self._btc(ctx, address, result)
        if is_eth:
            await self._eth(ctx, address, result)

    async def _btc(self, ctx: Context, address: str, result: ModuleResult) -> None:
        resp = await ctx.http.get(f"https://blockstream.info/api/address/{address}", retries=1)
        data = resp.json() or {}
        chain = data.get("chain_stats") or {}
        mempool = data.get("mempool_stats") or {}
        if resp.ok and chain:
            funded = chain.get("funded_txo_sum", 0)
            spent = chain.get("spent_txo_sum", 0)
            balance = (funded - spent) / 1e8
            self.add_finding(result, source="blockstream", category="crypto", kind="balance", confidence="high",
                             title=f"Bitcoin: баланс {balance:.8f} BTC, транзакций {chain.get('tx_count')}, "
                                   f"в мемпуле {mempool.get('tx_count', 0)}",
                             url=f"https://blockstream.info/address/{address}", value=address,
                             data={"balance_btc": balance, "total_received_btc": funded / 1e8,
                                   "total_sent_btc": spent / 1e8, "tx_count": chain.get("tx_count"),
                                   "mempool_tx": mempool.get("tx_count"),
                                   "utxo_count": chain.get("funded_txo_count")},
                             evidence=f"blockstream.info API: chain_stats={chain}", http_code=resp.status_code)
            self.add_status(result, SourceStatus(source="blockstream", category="crypto", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="blockstream", category="crypto", status="error",
                                                 http_code=resp.status_code or None,
                                                 error=resp.error or str(data)[:120]))
        txs = await ctx.http.get(f"https://blockstream.info/api/address/{address}/txs", retries=1)
        txdata = txs.json()
        if isinstance(txdata, list) and txdata:
            recent = [{"txid": t.get("txid"), "date": _ts(t.get("status", {}).get("block_time")),
                       "fee": t.get("fee"), "size": t.get("size"),
                       "in": len(t.get("vin", [])), "out": len(t.get("vout", [])),
                       "confirmed": t.get("status", {}).get("confirmed"),
                       "url": f"https://blockstream.info/tx/{t.get('txid')}"} for t in txdata[:10]]
            self.add_finding(result, source="blockstream-txs", category="crypto", kind="transactions",
                             confidence="high",
                             title=f"Последние транзакции: {len(recent)} (первая {recent[0]['date']})",
                             url=f"https://blockstream.info/address/{address}", value=address,
                             data={"transactions": recent,
                                   "first_seen": recent[-1]["date"] if recent else None},
                             evidence=f"blockstream.info /txs → {len(txdata)} транзакций", http_code=txs.status_code)

    async def _eth(self, ctx: Context, address: str, result: ModuleResult) -> None:
        resp = await ctx.http.get(f"https://api.blockchair.com/ethereum/dashboards/address/{address}",
                                  retries=1)
        data = resp.json() or {}
        payload = (data.get("data") or {}).get(address.lower()) or (data.get("data") or {}).get(address)
        if resp.ok and payload:
            info = payload.get("address", payload) if isinstance(payload, dict) else {}
            self.add_finding(result, source="blockchair", category="crypto", kind="balance", confidence="high",
                             title=f"Ethereum: баланс {info.get('balance', 0) / 1e18:.6f} ETH, "
                                   f"транзакций {info.get('transaction_count')}, "
                                   f"получено {info.get('received', 0) / 1e18:.4f} ETH",
                             url=f"https://blockchair.com/ethereum/address/{address}", value=address,
                             data={"balance_eth": info.get("balance", 0) / 1e18,
                                   "received_eth": info.get("received", 0) / 1e18,
                                   "spent_eth": info.get("spent", 0) / 1e18,
                                   "tx_count": info.get("transaction_count"),
                                   "first_seen": info.get("first_seen_receiving") or info.get("time_first_incoming"),
                                   "last_seen": info.get("last_seen_receiving") or info.get("time_last_incoming"),
                                   "type": info.get("type")},
                             evidence=f"blockchair ethereum dashboard: balance={info.get('balance')}, "
                                      f"tx={info.get('transaction_count')}", http_code=resp.status_code)
            self.add_status(result, SourceStatus(source="blockchair", category="crypto", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="blockchair", category="crypto", status="error",
                                                 http_code=resp.status_code or None,
                                                 error=resp.error or str(data)[:150]))
        ethplorer = await ctx.http.get(f"https://api.ethplorer.io/getAddressInfo/{address}",
                                       params={"apiKey": "freekey"}, retries=1)
        edata = ethplorer.json() or {}
        if ethplorer.ok and edata.get("address"):
            tokens = edata.get("tokens") or []
            self.add_finding(result, source="ethplorer", category="crypto", kind="tokens", confidence="high",
                             title=f"Ethereum: токенов на адресе {len(tokens)}, транзакций "
                                   f"{(edata.get('countTxs') or 0)}",
                             url=f"https://ethplorer.io/address/{address}", value=address,
                             data={"count_txs": edata.get("countTxs"),
                                   "eth_balance": (edata.get("ETH") or {}).get("balance"),
                                   "tokens": [{"symbol": (t.get("tokenInfo") or {}).get("symbol"),
                                               "name": (t.get("tokenInfo") or {}).get("name"),
                                               "balance": t.get("balance"), "address": t.get("tokenInfo", {}).get("address")}
                                              for t in tokens[:15]]},
                             evidence=f"ethplorer getAddressInfo → countTxs={edata.get('countTxs')}, "
                                      f"tokens={len(tokens)}", http_code=ethplorer.status_code)
            self.add_status(result, SourceStatus(source="ethplorer", category="crypto", status="found",
                                                 http_code=ethplorer.status_code, url=ethplorer.url))


def _ts(value) -> str:
    import time
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(value)))
    except Exception:
        return "—"
