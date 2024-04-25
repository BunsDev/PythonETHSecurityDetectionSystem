import { Component, OnInit } from '@angular/core';
import { FraudAnalysisService } from '../../fraud-analysis.service';
import { UserService } from '../../user.service';

@Component({
  selector: 'app-fraud-analysis-history',
  templateUrl: './fraud-analysis-history.component.html',
  styleUrls: ['./fraud-analysis-history.component.css']
})
export class FraudAnalysisHistoryComponent implements OnInit {
  fraudAnalysisHistory: any[] = []; // Initialize the property
  selectedAnalysis: any = null; // Initialize the property
  editMode: boolean = false; // Initialize the property
  editingAnalysis: any = null; 

  searchName: string = '';
  searchType: string = '';
  searchOwnershipFrom: string = '';
  searchOwnershipTo: string = '';
  searchLikelihood: string = '';
  searchTypeOther: string = '';

  constructor(
    private fraudAnalysisService: FraudAnalysisService,
    private userService: UserService
  ) {}

  ngOnInit(): void {
    this.getFraudAnalysisHistory();
  }

  // Define getFraudAnalysisHistory method
  getFraudAnalysisHistory(): void {
    const currentUser = this.userService.currentUserValue; // Handle potential undefined value
    if (currentUser && currentUser.id) {
      this.fraudAnalysisService.getFraudAnalysisHistory(currentUser.id).subscribe(
        (history) => {
          this.fraudAnalysisHistory = history;
        },
        (error) => console.error('Error fetching fraud analysis history:', error)
      );
    } else {
      console.error('User ID is undefined.');
    }
  }
  
  search(): void {
    const userId = this.userService.currentUserValue?.id;
    if (typeof userId === 'number') {
      const params = {
        name: this.searchName,
        type: this.searchType,
        ownershipFrom: this.searchOwnershipFrom,
        ownershipTo: this.searchOwnershipTo,
        likelihood: this.searchLikelihood
      };
  
      this.fraudAnalysisService.searchFraudAnalysis(userId, params).subscribe(
        (results) => {
          this.fraudAnalysisHistory = results;
        },
        (error) => {
          console.error('Search error:', error);
          alert('Search operation failed: ' + error.message);
        }
      );
    } else {
      console.error('User ID is undefined');
    } 
  }     

  selectAnalysis(analysis: any): void {
    console.log('Analysis selected:', analysis);
    this.selectedAnalysis = analysis; // Deep clone to avoid direct reference
    this.editMode = false; // Exit edit mode when a new analysis is selected
  }

  startEdit(): void {
    this.editMode = true;
    console.log('Sending for update:', this.editingAnalysis);
    // Optionally make a deep clone if you want to allow canceling edits
    this.editingAnalysis = JSON.parse(JSON.stringify(this.selectedAnalysis));
  }
  

  saveEdit(): void {
  if (this.selectedAnalysis && window.confirm('Are you sure you want to save the changes?')) {
    console.log('Attempting to save edit:', this.selectedAnalysis); // Log the data being sent

    // Use this.selectedAnalysis.id and this.selectedAnalysis to reflect the updated values
    this.fraudAnalysisService.updateFraudAnalysis(this.selectedAnalysis.id, this.selectedAnalysis).subscribe(
      () => {
        this.getFraudAnalysisHistory(); // Refresh list
        this.editMode = false; // Exit edit mode
        // Optionally reset editingAnalysis if you plan to use it for other purposes
        this.editingAnalysis = null; 
        alert('Saved Result Successfully.');
      },
      (error) => {
        console.error('Error saving fraud analysis:', error);  // Log any error response
        alert('Save operation failed: ' + error.message);
        // No need to revert to editMode=true here since we want the user to be able to retry or cancel
      }
    );
  }
}

  cancelEdit(): void {
    this.editMode = false;
    // Reset the editingAnalysis object if you created one during startEdit
    this.editingAnalysis = null;
  }

  deleteAnalysis(analysisId: number): void {
    const confirmation = confirm('Are you sure you want to delete this analysis?');
    if (confirmation) {
      this.fraudAnalysisService.deleteFraudAnalysis(analysisId).subscribe(
        () => {
          this.getFraudAnalysisHistory(); // Update the list
          this.selectedAnalysis = null; // Clear selection
          alert('Deleted Result Successfully.');
        },
        (error) => {
          console.error('Error deleting fraud analysis:', error);
        }
      );
    }
  }
}
  
