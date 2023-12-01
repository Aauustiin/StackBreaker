
graph_test:     file format elf32-i386


Disassembly of section .init:

00000358 <_init>:
 358:	53                   	push   %ebx
 359:	83 ec 08             	sub    $0x8,%esp
 35c:	e8 8f 00 00 00       	call   3f0 <__x86.get_pc_thunk.bx>
 361:	81 c3 7b 1c 00 00    	add    $0x1c7b,%ebx
 367:	8b 83 18 00 00 00    	mov    0x18(%ebx),%eax
 36d:	85 c0                	test   %eax,%eax
 36f:	74 05                	je     376 <_init+0x1e>
 371:	e8 32 00 00 00       	call   3a8 <__gmon_start__@plt>
 376:	83 c4 08             	add    $0x8,%esp
 379:	5b                   	pop    %ebx
 37a:	c3                   	ret    

Disassembly of section .plt:

00000380 <.plt>:
 380:	ff b3 04 00 00 00    	pushl  0x4(%ebx)
 386:	ff a3 08 00 00 00    	jmp    *0x8(%ebx)
 38c:	00 00                	add    %al,(%eax)
	...

00000390 <__libc_start_main@plt>:
 390:	ff a3 0c 00 00 00    	jmp    *0xc(%ebx)
 396:	68 00 00 00 00       	push   $0x0
 39b:	e9 e0 ff ff ff       	jmp    380 <.plt>

Disassembly of section .plt.got:

000003a0 <__cxa_finalize@plt>:
 3a0:	ff a3 14 00 00 00    	jmp    *0x14(%ebx)
 3a6:	66 90                	xchg   %ax,%ax

000003a8 <__gmon_start__@plt>:
 3a8:	ff a3 18 00 00 00    	jmp    *0x18(%ebx)
 3ae:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

000003b0 <_start>:
 3b0:	31 ed                	xor    %ebp,%ebp
 3b2:	5e                   	pop    %esi
 3b3:	89 e1                	mov    %esp,%ecx
 3b5:	83 e4 f0             	and    $0xfffffff0,%esp
 3b8:	50                   	push   %eax
 3b9:	54                   	push   %esp
 3ba:	52                   	push   %edx
 3bb:	e8 22 00 00 00       	call   3e2 <_start+0x32>
 3c0:	81 c3 1c 1c 00 00    	add    $0x1c1c,%ebx
 3c6:	8d 83 34 e6 ff ff    	lea    -0x19cc(%ebx),%eax
 3cc:	50                   	push   %eax
 3cd:	8d 83 d4 e5 ff ff    	lea    -0x1a2c(%ebx),%eax
 3d3:	50                   	push   %eax
 3d4:	51                   	push   %ecx
 3d5:	56                   	push   %esi
 3d6:	ff b3 1c 00 00 00    	pushl  0x1c(%ebx)
 3dc:	e8 af ff ff ff       	call   390 <__libc_start_main@plt>
 3e1:	f4                   	hlt    
 3e2:	8b 1c 24             	mov    (%esp),%ebx
 3e5:	c3                   	ret    
 3e6:	66 90                	xchg   %ax,%ax
 3e8:	66 90                	xchg   %ax,%ax
 3ea:	66 90                	xchg   %ax,%ax
 3ec:	66 90                	xchg   %ax,%ax
 3ee:	66 90                	xchg   %ax,%ax

000003f0 <__x86.get_pc_thunk.bx>:
 3f0:	8b 1c 24             	mov    (%esp),%ebx
 3f3:	c3                   	ret    
 3f4:	66 90                	xchg   %ax,%ax
 3f6:	66 90                	xchg   %ax,%ax
 3f8:	66 90                	xchg   %ax,%ax
 3fa:	66 90                	xchg   %ax,%ax
 3fc:	66 90                	xchg   %ax,%ax
 3fe:	66 90                	xchg   %ax,%ax

00000400 <deregister_tm_clones>:
 400:	e8 e4 00 00 00       	call   4e9 <__x86.get_pc_thunk.dx>
 405:	81 c2 d7 1b 00 00    	add    $0x1bd7,%edx
 40b:	8d 8a 2c 00 00 00    	lea    0x2c(%edx),%ecx
 411:	8d 82 2c 00 00 00    	lea    0x2c(%edx),%eax
 417:	39 c8                	cmp    %ecx,%eax
 419:	74 1d                	je     438 <deregister_tm_clones+0x38>
 41b:	8b 82 10 00 00 00    	mov    0x10(%edx),%eax
 421:	85 c0                	test   %eax,%eax
 423:	74 13                	je     438 <deregister_tm_clones+0x38>
 425:	55                   	push   %ebp
 426:	89 e5                	mov    %esp,%ebp
 428:	83 ec 14             	sub    $0x14,%esp
 42b:	51                   	push   %ecx
 42c:	ff d0                	call   *%eax
 42e:	83 c4 10             	add    $0x10,%esp
 431:	c9                   	leave  
 432:	c3                   	ret    
 433:	90                   	nop
 434:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
 438:	f3 c3                	repz ret 
 43a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00000440 <register_tm_clones>:
 440:	e8 a4 00 00 00       	call   4e9 <__x86.get_pc_thunk.dx>
 445:	81 c2 97 1b 00 00    	add    $0x1b97,%edx
 44b:	55                   	push   %ebp
 44c:	8d 8a 2c 00 00 00    	lea    0x2c(%edx),%ecx
 452:	8d 82 2c 00 00 00    	lea    0x2c(%edx),%eax
 458:	29 c8                	sub    %ecx,%eax
 45a:	89 e5                	mov    %esp,%ebp
 45c:	53                   	push   %ebx
 45d:	c1 f8 02             	sar    $0x2,%eax
 460:	89 c3                	mov    %eax,%ebx
 462:	83 ec 04             	sub    $0x4,%esp
 465:	c1 eb 1f             	shr    $0x1f,%ebx
 468:	01 d8                	add    %ebx,%eax
 46a:	d1 f8                	sar    %eax
 46c:	74 14                	je     482 <register_tm_clones+0x42>
 46e:	8b 92 20 00 00 00    	mov    0x20(%edx),%edx
 474:	85 d2                	test   %edx,%edx
 476:	74 0a                	je     482 <register_tm_clones+0x42>
 478:	83 ec 08             	sub    $0x8,%esp
 47b:	50                   	push   %eax
 47c:	51                   	push   %ecx
 47d:	ff d2                	call   *%edx
 47f:	83 c4 10             	add    $0x10,%esp
 482:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 485:	c9                   	leave  
 486:	c3                   	ret    
 487:	89 f6                	mov    %esi,%esi
 489:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

00000490 <__do_global_dtors_aux>:
 490:	55                   	push   %ebp
 491:	89 e5                	mov    %esp,%ebp
 493:	53                   	push   %ebx
 494:	e8 57 ff ff ff       	call   3f0 <__x86.get_pc_thunk.bx>
 499:	81 c3 43 1b 00 00    	add    $0x1b43,%ebx
 49f:	83 ec 04             	sub    $0x4,%esp
 4a2:	80 bb 2c 00 00 00 00 	cmpb   $0x0,0x2c(%ebx)
 4a9:	75 27                	jne    4d2 <__do_global_dtors_aux+0x42>
 4ab:	8b 83 14 00 00 00    	mov    0x14(%ebx),%eax
 4b1:	85 c0                	test   %eax,%eax
 4b3:	74 11                	je     4c6 <__do_global_dtors_aux+0x36>
 4b5:	83 ec 0c             	sub    $0xc,%esp
 4b8:	ff b3 28 00 00 00    	pushl  0x28(%ebx)
 4be:	e8 dd fe ff ff       	call   3a0 <__cxa_finalize@plt>
 4c3:	83 c4 10             	add    $0x10,%esp
 4c6:	e8 35 ff ff ff       	call   400 <deregister_tm_clones>
 4cb:	c6 83 2c 00 00 00 01 	movb   $0x1,0x2c(%ebx)
 4d2:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 4d5:	c9                   	leave  
 4d6:	c3                   	ret    
 4d7:	89 f6                	mov    %esi,%esi
 4d9:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

000004e0 <frame_dummy>:
 4e0:	55                   	push   %ebp
 4e1:	89 e5                	mov    %esp,%ebp
 4e3:	5d                   	pop    %ebp
 4e4:	e9 57 ff ff ff       	jmp    440 <register_tm_clones>

000004e9 <__x86.get_pc_thunk.dx>:
 4e9:	8b 14 24             	mov    (%esp),%edx
 4ec:	c3                   	ret    

000004ed <c>:
 4ed:	55                   	push   %ebp
 4ee:	89 e5                	mov    %esp,%ebp
 4f0:	83 ec 08             	sub    $0x8,%esp
 4f3:	e8 ae 00 00 00       	call   5a6 <__x86.get_pc_thunk.ax>
 4f8:	05 e4 1a 00 00       	add    $0x1ae4,%eax
 4fd:	e8 50 00 00 00       	call   552 <a>
 502:	b8 00 00 00 00       	mov    $0x0,%eax
 507:	c9                   	leave  
 508:	c3                   	ret    

00000509 <e>:
 509:	55                   	push   %ebp
 50a:	89 e5                	mov    %esp,%ebp
 50c:	e8 95 00 00 00       	call   5a6 <__x86.get_pc_thunk.ax>
 511:	05 cb 1a 00 00       	add    $0x1acb,%eax
 516:	b8 00 00 00 00       	mov    $0x0,%eax
 51b:	5d                   	pop    %ebp
 51c:	c3                   	ret    

0000051d <b>:
 51d:	55                   	push   %ebp
 51e:	89 e5                	mov    %esp,%ebp
 520:	83 ec 08             	sub    $0x8,%esp
 523:	e8 7e 00 00 00       	call   5a6 <__x86.get_pc_thunk.ax>
 528:	05 b4 1a 00 00       	add    $0x1ab4,%eax
 52d:	e8 bb ff ff ff       	call   4ed <c>
 532:	b8 00 00 00 00       	mov    $0x0,%eax
 537:	c9                   	leave  
 538:	c3                   	ret    

00000539 <d>:
 539:	55                   	push   %ebp
 53a:	89 e5                	mov    %esp,%ebp
 53c:	e8 65 00 00 00       	call   5a6 <__x86.get_pc_thunk.ax>
 541:	05 9b 1a 00 00       	add    $0x1a9b,%eax
 546:	e8 be ff ff ff       	call   509 <e>
 54b:	b8 00 00 00 00       	mov    $0x0,%eax
 550:	5d                   	pop    %ebp
 551:	c3                   	ret    

00000552 <a>:
 552:	55                   	push   %ebp
 553:	89 e5                	mov    %esp,%ebp
 555:	83 ec 08             	sub    $0x8,%esp
 558:	e8 49 00 00 00       	call   5a6 <__x86.get_pc_thunk.ax>
 55d:	05 7f 1a 00 00       	add    $0x1a7f,%eax
 562:	e8 b6 ff ff ff       	call   51d <b>
 567:	e8 cd ff ff ff       	call   539 <d>
 56c:	e8 e1 ff ff ff       	call   552 <a>
 571:	b8 00 00 00 00       	mov    $0x0,%eax
 576:	c9                   	leave  
 577:	c3                   	ret    

00000578 <main>:
 578:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 57c:	83 e4 f0             	and    $0xfffffff0,%esp
 57f:	ff 71 fc             	pushl  -0x4(%ecx)
 582:	55                   	push   %ebp
 583:	89 e5                	mov    %esp,%ebp
 585:	51                   	push   %ecx
 586:	83 ec 04             	sub    $0x4,%esp
 589:	e8 18 00 00 00       	call   5a6 <__x86.get_pc_thunk.ax>
 58e:	05 4e 1a 00 00       	add    $0x1a4e,%eax
 593:	e8 ba ff ff ff       	call   552 <a>
 598:	b8 00 00 00 00       	mov    $0x0,%eax
 59d:	83 c4 04             	add    $0x4,%esp
 5a0:	59                   	pop    %ecx
 5a1:	5d                   	pop    %ebp
 5a2:	8d 61 fc             	lea    -0x4(%ecx),%esp
 5a5:	c3                   	ret    

000005a6 <__x86.get_pc_thunk.ax>:
 5a6:	8b 04 24             	mov    (%esp),%eax
 5a9:	c3                   	ret    
 5aa:	66 90                	xchg   %ax,%ax
 5ac:	66 90                	xchg   %ax,%ax
 5ae:	66 90                	xchg   %ax,%ax

000005b0 <__libc_csu_init>:
 5b0:	55                   	push   %ebp
 5b1:	57                   	push   %edi
 5b2:	56                   	push   %esi
 5b3:	53                   	push   %ebx
 5b4:	e8 37 fe ff ff       	call   3f0 <__x86.get_pc_thunk.bx>
 5b9:	81 c3 23 1a 00 00    	add    $0x1a23,%ebx
 5bf:	83 ec 0c             	sub    $0xc,%esp
 5c2:	8b 6c 24 28          	mov    0x28(%esp),%ebp
 5c6:	8d b3 04 ff ff ff    	lea    -0xfc(%ebx),%esi
 5cc:	e8 87 fd ff ff       	call   358 <_init>
 5d1:	8d 83 00 ff ff ff    	lea    -0x100(%ebx),%eax
 5d7:	29 c6                	sub    %eax,%esi
 5d9:	c1 fe 02             	sar    $0x2,%esi
 5dc:	85 f6                	test   %esi,%esi
 5de:	74 25                	je     605 <__libc_csu_init+0x55>
 5e0:	31 ff                	xor    %edi,%edi
 5e2:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
 5e8:	83 ec 04             	sub    $0x4,%esp
 5eb:	55                   	push   %ebp
 5ec:	ff 74 24 2c          	pushl  0x2c(%esp)
 5f0:	ff 74 24 2c          	pushl  0x2c(%esp)
 5f4:	ff 94 bb 00 ff ff ff 	call   *-0x100(%ebx,%edi,4)
 5fb:	83 c7 01             	add    $0x1,%edi
 5fe:	83 c4 10             	add    $0x10,%esp
 601:	39 fe                	cmp    %edi,%esi
 603:	75 e3                	jne    5e8 <__libc_csu_init+0x38>
 605:	83 c4 0c             	add    $0xc,%esp
 608:	5b                   	pop    %ebx
 609:	5e                   	pop    %esi
 60a:	5f                   	pop    %edi
 60b:	5d                   	pop    %ebp
 60c:	c3                   	ret    
 60d:	8d 76 00             	lea    0x0(%esi),%esi

00000610 <__libc_csu_fini>:
 610:	f3 c3                	repz ret 

Disassembly of section .fini:

00000614 <_fini>:
 614:	53                   	push   %ebx
 615:	83 ec 08             	sub    $0x8,%esp
 618:	e8 d3 fd ff ff       	call   3f0 <__x86.get_pc_thunk.bx>
 61d:	81 c3 bf 19 00 00    	add    $0x19bf,%ebx
 623:	83 c4 08             	add    $0x8,%esp
 626:	5b                   	pop    %ebx
 627:	c3                   	ret    
