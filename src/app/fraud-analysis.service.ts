import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})


export class FraudAnalysisService {
  private apiUrl = 'http://localhost:5000';

  constructor(private http: HttpClient) { }

  // Helper method to format content
  private formatContent(content: string): string {
    // Process markdown, newlines, and sub-titles
    return content
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')  // Bold markdown to HTML
      .replace(/\n/g, '<br>')  // Newlines to HTML breaks
      .replace(/(\d\.\s)(.*?):/g, '<br><span class="subtitle">$1$2:</span>')  // Subtitles with numbers to HTML with subtitle class
      .replace(/(\d\.\s)([^\n]+)(\n|$)/g, '<br><span class="subtitle">$1</span><span class="sub-content">$2</span>');  // Subtitles without colon to HTML with sub-content class
  }

  // Utility function to escape special characters for JSON string
  escapeForJson(str: string): string {
    return str
      .replace(/\\/g, '\\\\')  // Escape backslashes
      .replace(/"/g, '\\"')    // Escape double-quotes
      .replace(/\n/g, '\\n')   // Escape newlines
      // ... add other escapes if necessary
  }


  getFraudAnalysisHistory(userId: number): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/fraudAnalysisHistory/${userId}`);
  }

  searchFraudAnalysis(userId: number, searchParams: any): Observable<any[]> {
    // Create an object with the search parameters
    const params = new HttpParams({
      fromObject: {
        userId: userId.toString(),
        transactionName: searchParams.name,
        fraudType: searchParams.type,
        ownershipFrom: searchParams.ownershipFrom,
        ownershipTo: searchParams.ownershipTo,
        likelihoodOfFraud: searchParams.likelihood
      }
    });
  
    // Perform the GET request with the search parameters
    return this.http.get<any[]>(`${this.apiUrl}/searchFraudAnalysis`, { params });
  }


  // Send the transaction hash to the backend for analysis
  analyzeFraudTransaction(transactionHash: string): Observable<any> {
    const apiUrl = `${this.apiUrl}/detect_fraud`;
    const payload = { hash: transactionHash };
    return this.http.post<any>(apiUrl, payload);
  }


  // Save new fraud analysis result
  saveFraudAnalysis(fraudAnalysis: any, userId: number, transactionName: string, transactionHash: string): Observable<any> {
    const apiUrl = `${this.apiUrl}/saveFraudAnalysis`;
    const payload = {
      user_id: userId,
      transaction_name: transactionName,
      transaction_hash: transactionHash,
      fraud_analysis: fraudAnalysis // The backend expects this key
    };
    return this.http.post<any>(apiUrl, payload);
  }
  
  // Update existing fraud analysis result
  updateFraudAnalysis(fraudAnalysisId: number, fraudAnalysisData: any): Observable<any> {
    console.log('Updating fraud analysis with data:', fraudAnalysisData);
    return this.http.put<any>(`${this.apiUrl}/updateFraudAnalysis/${fraudAnalysisId}`, fraudAnalysisData);
  }


  // Delete fraud analysis result
  deleteFraudAnalysis(fraudAnalysisId: number): Observable<any> {
    return this.http.delete<any>(`${this.apiUrl}/deleteFraudAnalysis/${fraudAnalysisId}`);
  }

  // Format the analysis result to match your front-end structure
  public formatAnalysisResult(analysisData: any): any {
    // Extract the nested fraud_analysis if that's how your backend structures it
    const formattedResult = {
      likelihoodOfFraud: analysisData.fraud_analysis.Likelihood_of_Fraud_Or_Scam_In_Percentage,
      fraudTransactionType: analysisData.fraud_analysis.Type_of_The_Possible_Fraud,
      ownershipFrom: analysisData.fraud_analysis.Ownership_of_From_Address,
      ownershipTo: analysisData.fraud_analysis.Ownership_of_To_Address,
      behavior: analysisData.fraud_analysis.Behavior_of_the_From_and_To_Addresses,
      peculiarities: analysisData.fraud_analysis.Peculiarities_in_the_Transaction,
      broaderContext: analysisData.fraud_analysis.Market_Context_and_Alerts,
      supportingEvidence: analysisData.fraud_analysis.Supporting_Evidence_for_Assessment,
      recommendActions: analysisData.fraud_analysis.Recommended_Actions
    };

    // Transform peculiarities if necessary, for example:
    if (typeof formattedResult.peculiarities === 'object') {
      formattedResult.peculiarities = Object.entries(formattedResult.peculiarities)
        .map(([key, value]) => ({ key, value }));
    }

    return formattedResult;
  }
  
}


