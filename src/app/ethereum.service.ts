// src/app/ethereum.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class EthereumService {
  private apiUrl = 'https://api.etherscan.io/api';
  private apiKey = 'FIG3V7T6SKFEV5QMMPQIFJ1STMYUCVA6CC';
  private coingeckoApiUrl = 'https://api.coingecko.com/api/v3';

  constructor(private http: HttpClient) { }

  // Example function to get the latest block number
  getLatestBlockNumber(): Observable<any> {
    const params = `module=proxy&action=eth_blockNumber&apikey=${this.apiKey}`;
    return this.http.get(`${this.apiUrl}?${params}`);
  }

  getEtherPrice(): Observable<any> {
    // Replace with the API endpoint that provides Ether price
    return this.http.get(`${this.coingeckoApiUrl}/simple/price?ids=ethereum&vs_currencies=usd`);
  }

  getGasPrices(): Observable<any> {
    const params = `module=gastracker&action=gasoracle&apikey=${this.apiKey}`;
    return this.http.get(`${this.apiUrl}?${params}`);
  }
  
  getPendingTxCount(): Observable<any> {
    const params = `module=proxy&action=eth_getBlockTransactionCountByNumber&tag=pending&apikey=${this.apiKey}`;
    return this.http.get(`${this.apiUrl}?${params}`);
  }
  
  getNetworkHashrate(): Observable<any> {
    const params = `module=stats&action=ethsupply&apikey=${this.apiKey}`;
    return this.http.get(`${this.apiUrl}?${params}`);
  }


  getGasOracle(): Observable<any> {
    const params = `module=gastracker&action=gasoracle&apikey=${this.apiKey}`;
    return this.http.get(`${this.apiUrl}?${params}`);
  }

  getEthSupply(): Observable<any> {
    const params = `module=stats&action=ethsupply2&apikey=${this.apiKey}`;
    return this.http.get(`${this.apiUrl}?${params}`);
  }

  // Add more functions as needed to fetch different types of data
}
