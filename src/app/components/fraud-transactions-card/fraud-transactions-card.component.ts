import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FraudAnalysisService } from '../../fraud-analysis.service'; 
import { MatSnackBar } from '@angular/material/snack-bar';
import { UserService } from '../../user.service';


@Component({
  selector: 'app-fraud-transactions-card',
  templateUrl: './fraud-transactions-card.component.html',
  styleUrls: ['./fraud-transactions-card.component.css']
})


export class FraudTransactionsCardComponent {
  transactionName: string = '';  
  transactionHash: string = '';
  fraudAnalysisResult: any;
  isAnalyzing: boolean = false;

  constructor(
    private http: HttpClient,
    private fraudAnalysisService: FraudAnalysisService,
    private snackBar: MatSnackBar,
    private userService: UserService
  ) {}

  analyzeTransaction(): void {
    if (!this.transactionHash.trim()) {
      this.snackBar.open('Please enter a transaction hash.', 'Close', {
        duration: 3000,
        verticalPosition: 'top',
        horizontalPosition: 'center',
        panelClass: ['centered-snack-bar'] // Ensure this class is defined in your global styles.css
      });
      return;
    }

    this.isAnalyzing = true;  // Analysis starts, show the in-progress sign
    
    this.fraudAnalysisService.analyzeFraudTransaction(this.transactionHash).subscribe(
      (response: any) => {
        this.fraudAnalysisResult = this.fraudAnalysisService.formatAnalysisResult(response);
        this.isAnalyzing = false;  // Analysis complete, hide the in-progress sign
      },
      (error) => {
        console.error('API call failed:', error);
        this.snackBar.open('Analysis failed. Please try again.', 'Close', { 
          duration: 3000,
          verticalPosition: 'top',
          horizontalPosition: 'center',
          panelClass: ['centered-snack-bar'] // Custom CSS class
        });

        this.isAnalyzing = false;  // Error occurred, hide the in-progress sign
        
      }
    );
  }

  saveAnalysisResult(): void {
    const currentUser = this.userService.currentUserValue;
    if (!currentUser || !currentUser.id) {
      this.snackBar.open('User not logged in or user ID not available', 'Close', { 
        duration: 3000,
        verticalPosition: 'top',
        horizontalPosition: 'center',
        panelClass: ['centered-snack-bar'] // Custom CSS class
      });
      return;
    }
  
    const confirmation = confirm('Are you sure you want to save this analysis result?');
    if (confirmation) {
      this.fraudAnalysisService.saveFraudAnalysis(
        this.fraudAnalysisResult, // Send the whole result object
        currentUser.id,
        this.transactionName,
        this.transactionHash
      ).subscribe(
        () => {
          this.snackBar.open('Analysis result saved successfully.', 'Close', { 
            duration: 3000,
            verticalPosition: 'top',
            horizontalPosition: 'center',
            panelClass: ['centered-snack-bar'] // Custom CSS class
          });
        },
        (error) => {
          console.error('Failed to save analysis result:', error);
          this.snackBar.open('Failed to save analysis result. Please try again.', 'Close', { 
            duration: 3000,
            verticalPosition: 'top',
            horizontalPosition: 'center',
            panelClass: ['centered-snack-bar'] // Custom CSS class
          });
        }
      );
    }
  }


}
