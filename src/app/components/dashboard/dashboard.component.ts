import { Component, OnInit } from '@angular/core';
import { EthereumService } from '../../ethereum.service';

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent implements OnInit {
  latestBlockNumber: string = '';
  etherPrice: number | null = null;
  gasPrices: any;
  pendingTxCount: string = '';
  networkHashrate: string = '';
  ethSupplyData: any;
  
  // ... additional properties for other data

  constructor(private ethereumService: EthereumService) { }

  ngOnInit() {
    this.getLatestBlockNumber();
    this.getEtherPrice();
    this.getGasPrices();
    this.getEthSupply();
    // ... call other methods to fetch data
  }

  getLatestBlockNumber() {
    this.ethereumService.getLatestBlockNumber().subscribe(data => {
      this.latestBlockNumber = parseInt(data.result, 16).toString();
    });
  }

  getEtherPrice() {
    this.ethereumService.getEtherPrice().subscribe(data => {
      this.etherPrice = data.ethereum.usd;
    });
  }

  getGasPrices() {
    this.ethereumService.getGasPrices().subscribe(data => {
      if (data.status === '1') {
        this.gasPrices = data.result;
      } else {
        console.error('Failed to load gas prices');
      }
    }, error => {
      console.error('Error fetching gas prices:', error);
    });
  }
  
  getPendingTxCount() {
    this.ethereumService.getPendingTxCount().subscribe(data => {
      this.pendingTxCount = parseInt(data.result, 16).toString();
    });
  }
  
  getNetworkHashrate() {
    this.ethereumService.getNetworkHashrate().subscribe(data => {
      this.networkHashrate = data.result;
    });
  }

  getEthSupply() {
    this.ethereumService.getEthSupply().subscribe(data => {
      if (data.status === '1') {
        this.ethSupplyData = data.result;
      } else {
        console.error('Failed to load ETH supply data');
      }
    }, error => {
      console.error('Error fetching ETH supply data:', error);
    });
  }
  
}