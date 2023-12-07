
fuzz_test:     file format elf32-i386


Disassembly of section .init:

000004e0 <_init>:
 4e0:	53                   	push   %ebx
 4e1:	83 ec 08             	sub    $0x8,%esp
 4e4:	e8 37 01 00 00       	call   620 <__x86.get_pc_thunk.bx>
 4e9:	81 c3 c7 1a 00 00    	add    $0x1ac7,%ebx
 4ef:	8b 83 44 00 00 00    	mov    0x44(%ebx),%eax
 4f5:	85 c0                	test   %eax,%eax
 4f7:	74 05                	je     4fe <_init+0x1e>
 4f9:	e8 da 00 00 00       	call   5d8 <__gmon_start__@plt>
 4fe:	83 c4 08             	add    $0x8,%esp
 501:	5b                   	pop    %ebx
 502:	c3                   	ret    

Disassembly of section .plt:

00000510 <.plt>:
 510:	ff b3 04 00 00 00    	pushl  0x4(%ebx)
 516:	ff a3 08 00 00 00    	jmp    *0x8(%ebx)
 51c:	00 00                	add    %al,(%eax)
	...

00000520 <printf@plt>:
 520:	ff a3 0c 00 00 00    	jmp    *0xc(%ebx)
 526:	68 00 00 00 00       	push   $0x0
 52b:	e9 e0 ff ff ff       	jmp    510 <.plt>

00000530 <fclose@plt>:
 530:	ff a3 10 00 00 00    	jmp    *0x10(%ebx)
 536:	68 08 00 00 00       	push   $0x8
 53b:	e9 d0 ff ff ff       	jmp    510 <.plt>

00000540 <fread@plt>:
 540:	ff a3 14 00 00 00    	jmp    *0x14(%ebx)
 546:	68 10 00 00 00       	push   $0x10
 54b:	e9 c0 ff ff ff       	jmp    510 <.plt>

00000550 <strcpy@plt>:
 550:	ff a3 18 00 00 00    	jmp    *0x18(%ebx)
 556:	68 18 00 00 00       	push   $0x18
 55b:	e9 b0 ff ff ff       	jmp    510 <.plt>

00000560 <strerror@plt>:
 560:	ff a3 1c 00 00 00    	jmp    *0x1c(%ebx)
 566:	68 20 00 00 00       	push   $0x20
 56b:	e9 a0 ff ff ff       	jmp    510 <.plt>

00000570 <exit@plt>:
 570:	ff a3 20 00 00 00    	jmp    *0x20(%ebx)
 576:	68 28 00 00 00       	push   $0x28
 57b:	e9 90 ff ff ff       	jmp    510 <.plt>

00000580 <strlen@plt>:
 580:	ff a3 24 00 00 00    	jmp    *0x24(%ebx)
 586:	68 30 00 00 00       	push   $0x30
 58b:	e9 80 ff ff ff       	jmp    510 <.plt>

00000590 <__libc_start_main@plt>:
 590:	ff a3 28 00 00 00    	jmp    *0x28(%ebx)
 596:	68 38 00 00 00       	push   $0x38
 59b:	e9 70 ff ff ff       	jmp    510 <.plt>

000005a0 <fprintf@plt>:
 5a0:	ff a3 2c 00 00 00    	jmp    *0x2c(%ebx)
 5a6:	68 40 00 00 00       	push   $0x40
 5ab:	e9 60 ff ff ff       	jmp    510 <.plt>

000005b0 <fopen@plt>:
 5b0:	ff a3 30 00 00 00    	jmp    *0x30(%ebx)
 5b6:	68 48 00 00 00       	push   $0x48
 5bb:	e9 50 ff ff ff       	jmp    510 <.plt>

000005c0 <__errno_location@plt>:
 5c0:	ff a3 34 00 00 00    	jmp    *0x34(%ebx)
 5c6:	68 50 00 00 00       	push   $0x50
 5cb:	e9 40 ff ff ff       	jmp    510 <.plt>

Disassembly of section .plt.got:

000005d0 <__cxa_finalize@plt>:
 5d0:	ff a3 40 00 00 00    	jmp    *0x40(%ebx)
 5d6:	66 90                	xchg   %ax,%ax

000005d8 <__gmon_start__@plt>:
 5d8:	ff a3 44 00 00 00    	jmp    *0x44(%ebx)
 5de:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

000005e0 <_start>:
 5e0:	31 ed                	xor    %ebp,%ebp
 5e2:	5e                   	pop    %esi
 5e3:	89 e1                	mov    %esp,%ecx
 5e5:	83 e4 f0             	and    $0xfffffff0,%esp
 5e8:	50                   	push   %eax
 5e9:	54                   	push   %esp
 5ea:	52                   	push   %edx
 5eb:	e8 22 00 00 00       	call   612 <_start+0x32>
 5f0:	81 c3 c0 19 00 00    	add    $0x19c0,%ebx
 5f6:	8d 83 80 e9 ff ff    	lea    -0x1680(%ebx),%eax
 5fc:	50                   	push   %eax
 5fd:	8d 83 20 e9 ff ff    	lea    -0x16e0(%ebx),%eax
 603:	50                   	push   %eax
 604:	51                   	push   %ecx
 605:	56                   	push   %esi
 606:	ff b3 48 00 00 00    	pushl  0x48(%ebx)
 60c:	e8 7f ff ff ff       	call   590 <__libc_start_main@plt>
 611:	f4                   	hlt    
 612:	8b 1c 24             	mov    (%esp),%ebx
 615:	c3                   	ret    
 616:	66 90                	xchg   %ax,%ax
 618:	66 90                	xchg   %ax,%ax
 61a:	66 90                	xchg   %ax,%ax
 61c:	66 90                	xchg   %ax,%ax
 61e:	66 90                	xchg   %ax,%ax

00000620 <__x86.get_pc_thunk.bx>:
 620:	8b 1c 24             	mov    (%esp),%ebx
 623:	c3                   	ret    
 624:	66 90                	xchg   %ax,%ax
 626:	66 90                	xchg   %ax,%ax
 628:	66 90                	xchg   %ax,%ax
 62a:	66 90                	xchg   %ax,%ax
 62c:	66 90                	xchg   %ax,%ax
 62e:	66 90                	xchg   %ax,%ax

00000630 <deregister_tm_clones>:
 630:	e8 e4 00 00 00       	call   719 <__x86.get_pc_thunk.dx>
 635:	81 c2 7b 19 00 00    	add    $0x197b,%edx
 63b:	8d 8a 58 00 00 00    	lea    0x58(%edx),%ecx
 641:	8d 82 58 00 00 00    	lea    0x58(%edx),%eax
 647:	39 c8                	cmp    %ecx,%eax
 649:	74 1d                	je     668 <deregister_tm_clones+0x38>
 64b:	8b 82 38 00 00 00    	mov    0x38(%edx),%eax
 651:	85 c0                	test   %eax,%eax
 653:	74 13                	je     668 <deregister_tm_clones+0x38>
 655:	55                   	push   %ebp
 656:	89 e5                	mov    %esp,%ebp
 658:	83 ec 14             	sub    $0x14,%esp
 65b:	51                   	push   %ecx
 65c:	ff d0                	call   *%eax
 65e:	83 c4 10             	add    $0x10,%esp
 661:	c9                   	leave  
 662:	c3                   	ret    
 663:	90                   	nop
 664:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
 668:	f3 c3                	repz ret 
 66a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00000670 <register_tm_clones>:
 670:	e8 a4 00 00 00       	call   719 <__x86.get_pc_thunk.dx>
 675:	81 c2 3b 19 00 00    	add    $0x193b,%edx
 67b:	55                   	push   %ebp
 67c:	8d 8a 58 00 00 00    	lea    0x58(%edx),%ecx
 682:	8d 82 58 00 00 00    	lea    0x58(%edx),%eax
 688:	29 c8                	sub    %ecx,%eax
 68a:	89 e5                	mov    %esp,%ebp
 68c:	53                   	push   %ebx
 68d:	c1 f8 02             	sar    $0x2,%eax
 690:	89 c3                	mov    %eax,%ebx
 692:	83 ec 04             	sub    $0x4,%esp
 695:	c1 eb 1f             	shr    $0x1f,%ebx
 698:	01 d8                	add    %ebx,%eax
 69a:	d1 f8                	sar    %eax
 69c:	74 14                	je     6b2 <register_tm_clones+0x42>
 69e:	8b 92 4c 00 00 00    	mov    0x4c(%edx),%edx
 6a4:	85 d2                	test   %edx,%edx
 6a6:	74 0a                	je     6b2 <register_tm_clones+0x42>
 6a8:	83 ec 08             	sub    $0x8,%esp
 6ab:	50                   	push   %eax
 6ac:	51                   	push   %ecx
 6ad:	ff d2                	call   *%edx
 6af:	83 c4 10             	add    $0x10,%esp
 6b2:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 6b5:	c9                   	leave  
 6b6:	c3                   	ret    
 6b7:	89 f6                	mov    %esi,%esi
 6b9:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

000006c0 <__do_global_dtors_aux>:
 6c0:	55                   	push   %ebp
 6c1:	89 e5                	mov    %esp,%ebp
 6c3:	53                   	push   %ebx
 6c4:	e8 57 ff ff ff       	call   620 <__x86.get_pc_thunk.bx>
 6c9:	81 c3 e7 18 00 00    	add    $0x18e7,%ebx
 6cf:	83 ec 04             	sub    $0x4,%esp
 6d2:	80 bb 58 00 00 00 00 	cmpb   $0x0,0x58(%ebx)
 6d9:	75 27                	jne    702 <__do_global_dtors_aux+0x42>
 6db:	8b 83 40 00 00 00    	mov    0x40(%ebx),%eax
 6e1:	85 c0                	test   %eax,%eax
 6e3:	74 11                	je     6f6 <__do_global_dtors_aux+0x36>
 6e5:	83 ec 0c             	sub    $0xc,%esp
 6e8:	ff b3 54 00 00 00    	pushl  0x54(%ebx)
 6ee:	e8 dd fe ff ff       	call   5d0 <__cxa_finalize@plt>
 6f3:	83 c4 10             	add    $0x10,%esp
 6f6:	e8 35 ff ff ff       	call   630 <deregister_tm_clones>
 6fb:	c6 83 58 00 00 00 01 	movb   $0x1,0x58(%ebx)
 702:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 705:	c9                   	leave  
 706:	c3                   	ret    
 707:	89 f6                	mov    %esi,%esi
 709:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

00000710 <frame_dummy>:
 710:	55                   	push   %ebp
 711:	89 e5                	mov    %esp,%ebp
 713:	5d                   	pop    %ebp
 714:	e9 57 ff ff ff       	jmp    670 <register_tm_clones>

00000719 <__x86.get_pc_thunk.dx>:
 719:	8b 14 24             	mov    (%esp),%edx
 71c:	c3                   	ret    

0000071d <decide>:
 71d:	55                   	push   %ebp
 71e:	89 e5                	mov    %esp,%ebp
 720:	53                   	push   %ebx
 721:	83 ec 74             	sub    $0x74,%esp
 724:	e8 f7 fe ff ff       	call   620 <__x86.get_pc_thunk.bx>
 729:	81 c3 87 18 00 00    	add    $0x1887,%ebx
 72f:	83 ec 0c             	sub    $0xc,%esp
 732:	ff 75 08             	pushl  0x8(%ebp)
 735:	e8 46 fe ff ff       	call   580 <strlen@plt>
 73a:	83 c4 10             	add    $0x10,%esp
 73d:	83 f8 64             	cmp    $0x64,%eax
 740:	76 0a                	jbe    74c <decide+0x2f>
 742:	b8 00 00 00 00       	mov    $0x0,%eax
 747:	e9 8c 00 00 00       	jmp    7d8 <decide+0xbb>
 74c:	8b 45 08             	mov    0x8(%ebp),%eax
 74f:	0f b6 00             	movzbl (%eax),%eax
 752:	3c 68                	cmp    $0x68,%al
 754:	74 07                	je     75d <decide+0x40>
 756:	b8 00 00 00 00       	mov    $0x0,%eax
 75b:	eb 7b                	jmp    7d8 <decide+0xbb>
 75d:	8b 45 08             	mov    0x8(%ebp),%eax
 760:	83 c0 01             	add    $0x1,%eax
 763:	0f b6 00             	movzbl (%eax),%eax
 766:	3c 65                	cmp    $0x65,%al
 768:	74 07                	je     771 <decide+0x54>
 76a:	b8 00 00 00 00       	mov    $0x0,%eax
 76f:	eb 67                	jmp    7d8 <decide+0xbb>
 771:	8b 45 08             	mov    0x8(%ebp),%eax
 774:	83 c0 02             	add    $0x2,%eax
 777:	0f b6 00             	movzbl (%eax),%eax
 77a:	3c 6c                	cmp    $0x6c,%al
 77c:	74 07                	je     785 <decide+0x68>
 77e:	b8 00 00 00 00       	mov    $0x0,%eax
 783:	eb 53                	jmp    7d8 <decide+0xbb>
 785:	8b 45 08             	mov    0x8(%ebp),%eax
 788:	83 c0 03             	add    $0x3,%eax
 78b:	0f b6 00             	movzbl (%eax),%eax
 78e:	3c 6c                	cmp    $0x6c,%al
 790:	74 07                	je     799 <decide+0x7c>
 792:	b8 00 00 00 00       	mov    $0x0,%eax
 797:	eb 3f                	jmp    7d8 <decide+0xbb>
 799:	8b 45 08             	mov    0x8(%ebp),%eax
 79c:	83 c0 04             	add    $0x4,%eax
 79f:	0f b6 00             	movzbl (%eax),%eax
 7a2:	3c 6f                	cmp    $0x6f,%al
 7a4:	74 07                	je     7ad <decide+0x90>
 7a6:	b8 00 00 00 00       	mov    $0x0,%eax
 7ab:	eb 2b                	jmp    7d8 <decide+0xbb>
 7ad:	8b 45 08             	mov    0x8(%ebp),%eax
 7b0:	83 c0 05             	add    $0x5,%eax
 7b3:	0f b6 00             	movzbl (%eax),%eax
 7b6:	3c 0a                	cmp    $0xa,%al
 7b8:	74 07                	je     7c1 <decide+0xa4>
 7ba:	b8 00 00 00 00       	mov    $0x0,%eax
 7bf:	eb 17                	jmp    7d8 <decide+0xbb>
 7c1:	83 ec 08             	sub    $0x8,%esp
 7c4:	ff 75 08             	pushl  0x8(%ebp)
 7c7:	8d 45 93             	lea    -0x6d(%ebp),%eax
 7ca:	50                   	push   %eax
 7cb:	e8 80 fd ff ff       	call   550 <strcpy@plt>
 7d0:	83 c4 10             	add    $0x10,%esp
 7d3:	b8 00 00 00 00       	mov    $0x0,%eax
 7d8:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 7db:	c9                   	leave  
 7dc:	c3                   	ret    

000007dd <main>:
 7dd:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 7e1:	83 e4 f0             	and    $0xfffffff0,%esp
 7e4:	ff 71 fc             	pushl  -0x4(%ecx)
 7e7:	55                   	push   %ebp
 7e8:	89 e5                	mov    %esp,%ebp
 7ea:	53                   	push   %ebx
 7eb:	51                   	push   %ecx
 7ec:	81 ec c0 02 00 00    	sub    $0x2c0,%esp
 7f2:	e8 29 fe ff ff       	call   620 <__x86.get_pc_thunk.bx>
 7f7:	81 c3 b9 17 00 00    	add    $0x17b9,%ebx
 7fd:	89 c8                	mov    %ecx,%eax
 7ff:	83 38 02             	cmpl   $0x2,(%eax)
 802:	74 22                	je     826 <main+0x49>
 804:	8b 40 04             	mov    0x4(%eax),%eax
 807:	8b 00                	mov    (%eax),%eax
 809:	83 ec 08             	sub    $0x8,%esp
 80c:	50                   	push   %eax
 80d:	8d 83 a0 e9 ff ff    	lea    -0x1660(%ebx),%eax
 813:	50                   	push   %eax
 814:	e8 07 fd ff ff       	call   520 <printf@plt>
 819:	83 c4 10             	add    $0x10,%esp
 81c:	83 ec 0c             	sub    $0xc,%esp
 81f:	6a 00                	push   $0x0
 821:	e8 4a fd ff ff       	call   570 <exit@plt>
 826:	8b 40 04             	mov    0x4(%eax),%eax
 829:	83 c0 04             	add    $0x4,%eax
 82c:	8b 00                	mov    (%eax),%eax
 82e:	83 ec 08             	sub    $0x8,%esp
 831:	8d 93 cc e9 ff ff    	lea    -0x1634(%ebx),%edx
 837:	52                   	push   %edx
 838:	50                   	push   %eax
 839:	e8 72 fd ff ff       	call   5b0 <fopen@plt>
 83e:	83 c4 10             	add    $0x10,%esp
 841:	89 45 f4             	mov    %eax,-0xc(%ebp)
 844:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
 848:	75 38                	jne    882 <main+0xa5>
 84a:	e8 71 fd ff ff       	call   5c0 <__errno_location@plt>
 84f:	8b 00                	mov    (%eax),%eax
 851:	83 ec 0c             	sub    $0xc,%esp
 854:	50                   	push   %eax
 855:	e8 06 fd ff ff       	call   560 <strerror@plt>
 85a:	83 c4 10             	add    $0x10,%esp
 85d:	89 c2                	mov    %eax,%edx
 85f:	8b 83 3c 00 00 00    	mov    0x3c(%ebx),%eax
 865:	8b 00                	mov    (%eax),%eax
 867:	83 ec 04             	sub    $0x4,%esp
 86a:	52                   	push   %edx
 86b:	8d 93 cf e9 ff ff    	lea    -0x1631(%ebx),%edx
 871:	52                   	push   %edx
 872:	50                   	push   %eax
 873:	e8 28 fd ff ff       	call   5a0 <fprintf@plt>
 878:	83 c4 10             	add    $0x10,%esp
 87b:	b8 00 00 00 00       	mov    $0x0,%eax
 880:	eb 3e                	jmp    8c0 <main+0xe3>
 882:	ff 75 f4             	pushl  -0xc(%ebp)
 885:	6a 01                	push   $0x1
 887:	68 bb 02 00 00       	push   $0x2bb
 88c:	8d 85 38 fd ff ff    	lea    -0x2c8(%ebp),%eax
 892:	50                   	push   %eax
 893:	e8 a8 fc ff ff       	call   540 <fread@plt>
 898:	83 c4 10             	add    $0x10,%esp
 89b:	83 ec 0c             	sub    $0xc,%esp
 89e:	ff 75 f4             	pushl  -0xc(%ebp)
 8a1:	e8 8a fc ff ff       	call   530 <fclose@plt>
 8a6:	83 c4 10             	add    $0x10,%esp
 8a9:	83 ec 0c             	sub    $0xc,%esp
 8ac:	8d 85 38 fd ff ff    	lea    -0x2c8(%ebp),%eax
 8b2:	50                   	push   %eax
 8b3:	e8 65 fe ff ff       	call   71d <decide>
 8b8:	83 c4 10             	add    $0x10,%esp
 8bb:	b8 00 00 00 00       	mov    $0x0,%eax
 8c0:	8d 65 f8             	lea    -0x8(%ebp),%esp
 8c3:	59                   	pop    %ecx
 8c4:	5b                   	pop    %ebx
 8c5:	5d                   	pop    %ebp
 8c6:	8d 61 fc             	lea    -0x4(%ecx),%esp
 8c9:	c3                   	ret    
 8ca:	66 90                	xchg   %ax,%ax
 8cc:	66 90                	xchg   %ax,%ax
 8ce:	66 90                	xchg   %ax,%ax

000008d0 <__libc_csu_init>:
 8d0:	55                   	push   %ebp
 8d1:	57                   	push   %edi
 8d2:	56                   	push   %esi
 8d3:	53                   	push   %ebx
 8d4:	e8 47 fd ff ff       	call   620 <__x86.get_pc_thunk.bx>
 8d9:	81 c3 d7 16 00 00    	add    $0x16d7,%ebx
 8df:	83 ec 0c             	sub    $0xc,%esp
 8e2:	8b 6c 24 28          	mov    0x28(%esp),%ebp
 8e6:	8d b3 04 ff ff ff    	lea    -0xfc(%ebx),%esi
 8ec:	e8 ef fb ff ff       	call   4e0 <_init>
 8f1:	8d 83 00 ff ff ff    	lea    -0x100(%ebx),%eax
 8f7:	29 c6                	sub    %eax,%esi
 8f9:	c1 fe 02             	sar    $0x2,%esi
 8fc:	85 f6                	test   %esi,%esi
 8fe:	74 25                	je     925 <__libc_csu_init+0x55>
 900:	31 ff                	xor    %edi,%edi
 902:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
 908:	83 ec 04             	sub    $0x4,%esp
 90b:	55                   	push   %ebp
 90c:	ff 74 24 2c          	pushl  0x2c(%esp)
 910:	ff 74 24 2c          	pushl  0x2c(%esp)
 914:	ff 94 bb 00 ff ff ff 	call   *-0x100(%ebx,%edi,4)
 91b:	83 c7 01             	add    $0x1,%edi
 91e:	83 c4 10             	add    $0x10,%esp
 921:	39 fe                	cmp    %edi,%esi
 923:	75 e3                	jne    908 <__libc_csu_init+0x38>
 925:	83 c4 0c             	add    $0xc,%esp
 928:	5b                   	pop    %ebx
 929:	5e                   	pop    %esi
 92a:	5f                   	pop    %edi
 92b:	5d                   	pop    %ebp
 92c:	c3                   	ret    
 92d:	8d 76 00             	lea    0x0(%esi),%esi

00000930 <__libc_csu_fini>:
 930:	f3 c3                	repz ret 

Disassembly of section .fini:

00000934 <_fini>:
 934:	53                   	push   %ebx
 935:	83 ec 08             	sub    $0x8,%esp
 938:	e8 e3 fc ff ff       	call   620 <__x86.get_pc_thunk.bx>
 93d:	81 c3 73 16 00 00    	add    $0x1673,%ebx
 943:	83 c4 08             	add    $0x8,%esp
 946:	5b                   	pop    %ebx
 947:	c3                   	ret    
