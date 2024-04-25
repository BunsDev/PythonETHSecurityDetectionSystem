import { TestBed } from '@angular/core/testing';

import { FraudAnalysisService } from './fraud-analysis.service';

describe('FraudAnalysisService', () => {
  let service: FraudAnalysisService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(FraudAnalysisService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
