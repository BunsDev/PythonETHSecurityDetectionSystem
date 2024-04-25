import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';


@Injectable({
  providedIn: 'root'
})

export class SmartContractService {
  private apiUrl = 'http://localhost:5000';

  constructor(private http: HttpClient) {}

  getAnalysisHistory(userId: number): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/analysisHistory/${userId}`);
  }

  searchAnalysis(userId: number, name: string, type: string, date: string): Observable<any[]> {
    console.log('Search called with userId:', userId); 
    return this.http.get<any[]>(`${this.apiUrl}/searchAnalysis`, {
      params: { userId, name, type, date }
    });
  }

  // Utility function to escape special characters for JSON string
  escapeForJson(str: string): string {
    return str
      .replace(/\\/g, '\\\\')  // Escape backslashes
      .replace(/"/g, '\\"')    // Escape double-quotes
      .replace(/\n/g, '\\n')   // Escape newlines
      // ... add other escapes if necessary
  }

  analyzeSmartContract(solidityVersion: string, contractCode: string) {
    const apiUrl = 'http://localhost:5000/detect_vulnerability';
    const payload = {
      version: solidityVersion,
      code: this.escapeForJson(contractCode)
    };
    
    return this.http.post(apiUrl, payload);
  }

  // Save new smart contract analysis result
  saveContract(contractName: string, solidityVersion: string, smartContractCode: string, userId: number, vulnerabilities: any[]): Observable<any> {
    const contractData = {
      name: contractName,
      version: solidityVersion,
      code: smartContractCode,
      user_id: userId,
      vulnerabilities: vulnerabilities  // Pass the array of vulnerabilities
    };
  
    return this.http.post<any>(`${this.apiUrl}/saveContract`, contractData);
  }


  // Save updated smart contract analysis result
  updateContract(contractData: any): Observable<any> {
    return this.http.put<any>(`${this.apiUrl}/updateContract/${contractData.id}`, contractData);
  }

  // Save selected smart contract analysis result
  deleteContract(contractId: number): Observable<any> {
    return this.http.delete<any>(`${this.apiUrl}/deleteContract/${contractId}`);
  }
}


