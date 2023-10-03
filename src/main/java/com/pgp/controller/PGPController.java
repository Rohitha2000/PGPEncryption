package com.pgp.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.pgp.service.PGPService;

@RestController
public class PGPController {
	
	@Autowired
	PGPService service;
	
	@PostMapping("encrypt")
	public ResponseEntity<?> uploadWavfiles(@RequestParam("files") List<MultipartFile> files) throws Exception{
		service.encryptWavFiles(files);
		return new ResponseEntity<>("File Encryption Status", HttpStatus.OK);
	}

}
